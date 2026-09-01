import { HomeClient } from "./HomeClient";

export const metadata = {
  title: "RansomEye",
  description:
    "Alert correlation, deduplication and AI-driven incident analysis.",
};

export default function HomePage() {
  return <HomeClient />;
}
