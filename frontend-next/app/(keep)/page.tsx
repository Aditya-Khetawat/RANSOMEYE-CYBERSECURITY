import { CommandCenterView } from "@/entities/ransomeye/ui/CommandCenterView";

export const metadata = {
  title: "RansomEye | Command Center",
  description:
    "Real-time ransomware early warning across the endpoint fleet: the behavioral kill chain, current posture, and detection lead time.",
};

export default function CommandCenterPage() {
  return <CommandCenterView />;
}
