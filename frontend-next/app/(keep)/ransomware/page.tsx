import { redirect } from "next/navigation";

// RansomEye's ransomware dashboard is the product's home page now — this
// route stays only as a redirect for anyone with the old /ransomware link.
export default function RansomwarePage() {
  redirect("/");
}
