import mongoose from "mongoose";
import { seedBaseData } from "../services/seed.js";

export async function connectDatabase() {
  if (!process.env.MONGODB_URI) {
    console.warn("[db] MONGODB_URI is not configured. Database-backed API routes will return 503.");
    return false;
  }
  await mongoose.connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 8000,
  });
  await seedBaseData();
  console.info("[db] MongoDB connected and baseline roles/resources ensured.");
  return true;
}

export function databaseReady() {
  return mongoose.connection.readyState === 1;
}
