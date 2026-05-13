import { api } from "./client";
import type {
  SiemDestination,
  SiemDestinationCreate,
  SiemDestinationUpdate,
} from "@/types/api";

export const siemApi = {
  list: () => api<SiemDestination[]>("/api/siem/destinations"),
  create: (body: SiemDestinationCreate) =>
    api<SiemDestination>("/api/siem/destinations", { method: "POST", body }),
  update: (id: string, body: SiemDestinationUpdate) =>
    api<SiemDestination>(`/api/siem/destinations/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/siem/destinations/${id}`, { method: "DELETE" }),
};
