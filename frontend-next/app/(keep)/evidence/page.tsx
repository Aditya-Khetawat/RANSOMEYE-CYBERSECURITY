import { EvidenceView } from "@/entities/ransomeye/ui/EvidenceView";

export const metadata = {
  title: "RansomEye | Evidence",
  description:
    "Every ransomware verdict backed by observable behavioral evidence, mapped to MITRE ATT&CK — with the absences shown too.",
};

export default function EvidencePage() {
  return <EvidenceView />;
}
