import logo from "../assets/falcon-scan-logo.png";
import { BRAND } from "../brand";

export default function Logo({ size = 32 }: { size?: number }) {
  return <img src={logo} height={size} alt={`${BRAND.name} logo`} style={{ display: "block", width: "auto" }} />;
}
