import { IncidentsView } from "@/entities/ransomeye/ui/IncidentsView";

export const metadata = {
  title: "RansomEye | Incidents",
  description: "Confirmed and suspected ransomware activity across the endpoint fleet — not raw alerts.",
};

export default function IncidentsPage() {
  return <IncidentsView />;
}
