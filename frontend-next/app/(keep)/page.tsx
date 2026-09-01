import { RansomwareClient } from "./ransomware/RansomwareClient";

export const metadata = {
  title: "RansomEye | Ransomware Early Warning",
  description:
    "AI-powered real-time ransomware early warning: behavioral detection across file-system, process, privilege and network telemetry, explainable risk scoring, and approval-gated containment.",
};

export default function HomePage() {
  return <RansomwareClient />;
}
