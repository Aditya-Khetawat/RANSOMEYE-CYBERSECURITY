import { BlastRadiusView } from "@/entities/ransomeye/ui/BlastRadiusView";

export const metadata = {
  title: "RansomEye | Blast Radius",
  description:
    "Projected encryption impact if containment does not occur, and the containment-impact comparison.",
};

export default function BlastRadiusPage() {
  return <BlastRadiusView />;
}
