
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

const encoder = new TextEncoder();

async function hashToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(token),
  );
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function validString(value: unknown, max = 120): value is string {
  return typeof value === "string" &&
    value.trim().length > 0 &&
    value.trim().length <= max;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  const viewerCode = Deno.env.get("ROC_VIEWER_CODE");
  const coordinatorCode = Deno.env.get("ROC_COORDINATOR_CODE");
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

  if (!viewerCode || !coordinatorCode || !supabaseUrl || !serviceKey) {
    return json({ error: "Server configuration incomplete" }, 500);
  }

  const db = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  try {
    const body = await req.json();
    const action = body?.action;

    // Exchange the shared access code for a random, expiring session.
    if (action === "unlock") {
      if (!validString(body.code, 200)) {
        return json({ error: "Enter a valid access code" }, 400);
      }

      let role: "viewer" | "coordinator" | null = null;
      if (body.code === coordinatorCode) role = "coordinator";
      else if (body.code === viewerCode) role = "viewer";

      if (!role) return json({ error: "Invalid access code" }, 401);

      const bytes = crypto.getRandomValues(new Uint8Array(32));
      const token = Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);

      const { error } = await db.from("board_sessions").insert({
        token_hash: await hashToken(token),
        access_role: role,
        expires_at: expiresAt.toISOString(),
      });

      if (error) {
        console.error("Session creation failed:", error.message);
        return json({ error: "Could not create session" }, 500);
      }

      return json({
        access_token: token,
        token_type: "Bearer",
        expires_at: expiresAt.toISOString(),
        role,
      });
    }

    // Every other action requires a valid stored session.
    const authHeader = req.headers.get("Authorization") || "";
    const match = authHeader.match(/^Bearer ([a-f0-9]{64})$/i);
    if (!match) return json({ error: "Session required" }, 401);

    const { data: session, error: sessionError } = await db
      .from("board_sessions")
      .select("access_role, expires_at")
      .eq("token_hash", await hashToken(match[1]))
      .gt("expires_at", new Date().toISOString())
      .maybeSingle();

    if (sessionError || !session) {
      return json({ error: "Session expired or invalid. Unlock again." }, 401);
    }

    const role = session.access_role as string;
    const isCoordinator = role === "coordinator";

    if (action === "get-board") {
      const [peopleResult, leaveResult] = await Promise.all([
        db.from("roster_people")
          .select("id, full_name, team_name, active, created_at")
          .order("full_name"),
        db.from("roster_leave")
          .select(
            "id, person_id, leave_date, leave_type, portion, status, notes",
          )
          .order("leave_date"),
      ]);

      if (peopleResult.error || leaveResult.error) {
        console.error(
          "Board read failed:",
          peopleResult.error?.message,
          leaveResult.error?.message,
        );
        return json({ error: "Could not load roster" }, 500);
      }

      return json({
        role,
        people: peopleResult.data,
        leave: leaveResult.data,
      });
    }

    if (!isCoordinator) {
      return json({ error: "Coordinator access required" }, 403);
    }

    if (action === "add-person") {
      if (!validString(body.full_name, 120)) {
        return json({ error: "Enter the employee name" }, 400);
      }

      if (
        !["NA STP", "EU STP", "Scheduling"].includes(body.team_name)
      ) {
        return json({ error: "Invalid team" }, 400);
      }

      const { data, error } = await db.from("roster_people").insert({
        full_name: body.full_name.trim(),
        team_name: body.team_name,
      }).select().single();

      if (error) {
        console.error("Add person failed:", error.message);
        return json({ error: "Could not add employee" }, 500);
      }
      return json({ person: data }, 201);
    }

    if (action === "update-person") {
      if (!validString(body.id, 60)) {
        return json({ error: "Employee ID required" }, 400);
      }

      const updates: Record<string, unknown> = {};
      if (body.full_name !== undefined) {
        if (!validString(body.full_name, 120)) {
          return json({ error: "Invalid employee name" }, 400);
        }
        updates.full_name = body.full_name.trim();
      }
      if (body.team_name !== undefined) {
        if (!["NA STP", "EU STP", "Scheduling"].includes(body.team_name)) {
          return json({ error: "Invalid team" }, 400);
        }
        updates.team_name = body.team_name;
      }
      if (body.active !== undefined) {
        if (typeof body.active !== "boolean") {
          return json({ error: "Invalid active status" }, 400);
        }
        updates.active = body.active;
      }
      if (Object.keys(updates).length === 0) {
        return json({ error: "No changes supplied" }, 400);
      }

      const { data, error } = await db.from("roster_people")
        .update(updates).eq("id", body.id).select().maybeSingle();

      if (error) {
        console.error("Update person failed:", error.message);
        return json({ error: "Could not update employee" }, 500);
      }
      if (!data) return json({ error: "Employee not found" }, 404);
      return json({ person: data });
    }

    if (action === "set-leave") {
      if (
        !validString(body.person_id, 60) ||
        !validString(body.leave_date, 10) ||
        !/^\d{4}-\d{2}-\d{2}$/.test(body.leave_date) ||
        !["AL", "CL", "SL", "OPTIONAL_OFF", "OTHER"].includes(body.leave_type) ||
        !["full", "first_half", "second_half"].includes(body.portion ?? "full") ||
        !["approved", "pending", "rejected"].includes(body.status ?? "approved")
      ) {
        return json({ error: "Invalid leave details" }, 400);
      }

      const portion = body.portion ?? "full";
      const status = body.status ?? "approved";

      // A rejected leave is removed from the active leave calendar.
      if (status === "rejected") {
        const { error } = await db.from("roster_leave")
          .delete()
          .eq("person_id", body.person_id)
          .eq("leave_date", body.leave_date);

        if (error) return json({ error: "Could not remove leave" }, 500);
        return json({ success: true, rejected: true });
      }

      const { data: person, error: personError } = await db
        .from("roster_people")
        .select("id")
        .eq("id", body.person_id)
        .eq("active", true)
        .maybeSingle();

      if (personError || !person) {
        return json({ error: "Active employee not found" }, 404);
      }

      const leaveRecord = {
        person_id: body.person_id,
        leave_date: body.leave_date,
        leave_type: body.leave_type,
        portion,
        status,
        notes: typeof body.notes === "string"
          ? body.notes.trim().slice(0, 500)
          : null,
      };

      const { data, error } = await db.from("roster_leave")
        .upsert(leaveRecord, { onConflict: "person_id,leave_date" })
        .select().single();

      if (error) {
        console.error("Save leave failed:", error.message);
        return json({
          error: "Could not save leave. Check the database schema.",
        }, 500);
      }
      return json({ leave: data });
    }

    if (action === "delete-leave") {
      if (!validString(body.id, 60)) {
        return json({ error: "Leave record ID required" }, 400);
      }
      const { error } = await db.from("roster_leave")
        .delete().eq("id", body.id);
      if (error) return json({ error: "Could not delete leave" }, 500);
      return json({ success: true });
    }

    return json({ error: "Unknown action" }, 400);
  } catch (error) {
    console.error("Request failed:", error);
    return json({ error: "Invalid request" }, 400);
  }
});
