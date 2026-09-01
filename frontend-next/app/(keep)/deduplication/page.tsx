import { DeduplicationClient } from "./DeduplicationClient";

export default function Page() {
  return <DeduplicationClient />;
}

export const metadata = {
  title: "Deduplication | RansomEye",
  description: "Duplicate alert collapsing before correlation runs",
};
