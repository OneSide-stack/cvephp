import ReactDOM from "react-dom/client";
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/inter/700.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "@xterm/xterm/css/xterm.css";
import "./styles.css";
import App from "./App";
import { LabProvider } from "./lib/LabContext";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <LabProvider><App /></LabProvider>,
);

if (import.meta.env.PROD && "serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register(`${import.meta.env.BASE_URL}sw.js`).catch((error) => {
      console.warn("Offline shell registration failed", error);
    });
  });
}
