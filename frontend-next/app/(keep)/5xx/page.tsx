import { AlertFeed } from "@/entities/alertengine/ui/AlertFeed";

export const metadata = {
  title: "Critical | RansomEye",
};

export default function CriticalPage() {
  return (
    <AlertFeed
      criticalOnly
      title="Critical Alerts"
      subtitle="Critical-severity alerts only — the highest-impact slice of the batch."
    />
  );
}
