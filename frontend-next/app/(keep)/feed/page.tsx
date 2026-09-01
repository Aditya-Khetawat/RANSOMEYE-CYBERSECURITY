import { AlertFeed } from "@/entities/alertengine/ui/AlertFeed";

export const metadata = {
  title: "Alert Feed | RansomEye",
};

export default function FeedPage() {
  return (
    <AlertFeed
      title="Alert Feed"
      subtitle="Every alert ingested in the current batch, newest first."
    />
  );
}
