import { betterAuth } from "better-auth";
import { dbsc } from "@dbsc-toolkit/better-auth";
import Database from "better-sqlite3";

const db = new Database(process.env.DB_PATH ?? "./demo.sqlite");

export const auth = betterAuth({
  database: db,

  emailAndPassword: {
    enabled: true,
  },

  secret: process.env.BETTER_AUTH_SECRET ?? "dev-secret-change-in-production",

  baseURL:
    process.env.BASE_URL ??
    process.env.RENDER_EXTERNAL_URL ??
    "http://localhost:3000",

  plugins: [
    dbsc({
      basePath: "/api/auth",
      onEvent: (event) => {
        console.log(`[dbsc] ${event.type} session=${event.sessionId} tier=${event.tier}`);
      },
    }),
  ],
});
