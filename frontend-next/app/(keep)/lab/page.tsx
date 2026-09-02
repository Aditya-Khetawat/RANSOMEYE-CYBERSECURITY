import { AttackLab } from "@/entities/ransomeye/ui/AttackLab";

export const metadata = {
  title: "Attack Lab | RansomEye",
  description:
    "Launch a controlled ransomware attack against a synthetic endpoint and watch RansomEye detect and stop it before mass encryption — live, not pre-recorded.",
};

export default function AttackLabPage() {
  return <AttackLab />;
}
