import { DetectionView } from "@/entities/ransomeye/ui/DetectionView";

export const metadata = {
  title: "RansomEye | Ransomware Early Warning",
  description:
    "The behavioral signals RansomEye scores, the correlated verdict, and how much warning time it bought before encryption.",
};

export default function DetectionPage() {
  return <DetectionView />;
}
