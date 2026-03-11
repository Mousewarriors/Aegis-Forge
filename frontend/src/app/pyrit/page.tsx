import { redirect } from "next/navigation";

export default function PyritPage() {
    redirect("/eval?evaluator=pyrit");
}
