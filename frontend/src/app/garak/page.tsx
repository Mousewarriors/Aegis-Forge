import { redirect } from "next/navigation";

export default function GarakPage() {
    redirect("/eval?evaluator=garak");
}
