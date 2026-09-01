import { AlertFeed } from "@/entities/alertengine/ui/AlertFeed";

export const metadata = {
  title: "Firing | RansomEye",
};

export default function FiringPage() {
  return (
    <AlertFeed
      firingOnly
      title="Firing Alerts"
      subtitle="Alerts currently firing — resolved and suppressed alerts are hidden."
    />
  );
}
