import { Providers } from "./providers";
import "./globals.css";

export const metadata = {
  title: "Zetta DAI",
  description: "Wrap, stake, and earn with Zetta DAI",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
