import { EvaluationDashboard } from "@/entities/ransomeye/ui/EvaluationDashboard";

export const metadata = {
  title: "RansomEye | Can We Trust It?",
  description: "Detection precision, recall and false-positive rate measured across every scenario and seed.",
};

export default function EvaluationPage() {
  return <EvaluationDashboard />;
}
