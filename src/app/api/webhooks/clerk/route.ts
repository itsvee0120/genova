/* eslint-disable camelcase */
import { clerkClient, WebhookEvent } from "@clerk/nextjs/server";
import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { Webhook } from "svix";

import { createUser, deleteUser, updateUser } from "@/lib/actions/user.actions";

export async function POST(req: Request) {
  // Get the webhook secret from environment variables
  const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

  if (!WEBHOOK_SECRET) {
    return new Response("Please add WEBHOOK_SECRET to .env or .env.local", {
      status: 500,
    });
  }

  // Get the headers
  const headerPayload = await headers();
  const svix_id = headerPayload.get("svix-id");
  const svix_timestamp = headerPayload.get("svix-timestamp");
  const svix_signature = headerPayload.get("svix-signature");

  // If headers are missing, return an error
  if (!svix_id || !svix_timestamp || !svix_signature) {
    return new Response("Missing Svix headers", { status: 400 });
  }

  // Get the body of the request
  const payload = await req.json();
  const body = JSON.stringify(payload);

  // Create a new Svix instance with your secret
  const wh = new Webhook(WEBHOOK_SECRET);

  let evt: WebhookEvent;

  // Verify the payload with the headers
  try {
    evt = wh.verify(body, {
      "svix-id": svix_id,
      "svix-timestamp": svix_timestamp,
      "svix-signature": svix_signature,
    }) as WebhookEvent;
  } catch (err) {
    console.error("Error verifying webhook:", err);
    return new Response("Webhook verification failed", { status: 400 });
  }

  // Extract ID and event type
  const { id } = evt.data;
  const eventType = evt.type;

  // CREATE event handling
  if (eventType === "user.created") {
    const { email_addresses, image_url, first_name, last_name, username } =
      evt.data;

    if (!email_addresses || !username) {
      return new Response("Required fields missing", { status: 400 });
    }

    if (!id) {
      throw new Error("Clerk ID is missing");
    }

    const user = {
      clerkId: id,
      email: email_addresses[0].email_address,
      username: username!,
      firstName: first_name || "", // Default to empty string if null
      lastName: last_name || "", // Default to empty string if null
      photo: image_url,
    };
    try {
      const newUser = await createUser(user);

      // Set public metadata
      if (newUser) {
        const client = await clerkClient(); // Await the clerkClient() to get the ClerkClient instance
        await client.users.updateUserMetadata(id, {
          publicMetadata: {
            userId: newUser._id,
          },
        });

        return NextResponse.json({ message: "OK", user: newUser });
      }
    } catch (error) {
      console.error("Error creating user:", error);
      return new Response("Failed to create user", { status: 500 });
    }
  }

  // UPDATE event handling
  if (eventType === "user.updated") {
    const { image_url, first_name, last_name, username } = evt.data;

    if (!id) {
      return new Response("User ID missing", { status: 400 });
    }

    const user = {
      firstName: first_name ?? "",
      lastName: last_name ?? "",
      username: username ?? "",
      photo: image_url,
    };

    try {
      const updatedUser = await updateUser(id, user);
      return NextResponse.json({ message: "OK", user: updatedUser });
    } catch (error) {
      console.error("Error updating user:", error);
      return new Response("Failed to update user", { status: 500 });
    }
  }

  // DELETE event handling
  if (eventType === "user.deleted") {
    if (!id) {
      return new Response("User ID missing", { status: 400 });
    }

    try {
      const deletedUser = await deleteUser(id);
      return NextResponse.json({ message: "OK", user: deletedUser });
    } catch (error) {
      console.error("Error deleting user:", error);
      return new Response("Failed to delete user", { status: 500 });
    }
  }

  console.log(`Webhook with ID ${id} and type ${eventType}`);
  console.log("Webhook body:", body);

  return new Response("", { status: 200 });
}
