import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";

describe("App shell", () => {
  it("renders the vault navigation and main landmarks", () => {
    render(<App />);
    expect(screen.getByRole("navigation", { name: "Vault" })).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Items" })).toBeInTheDocument();
  });

  it("keeps the document title generic", () => {
    render(<App />);
    // Item titles must never appear in the document title (design-principles §5).
    expect(document.title).not.toMatch(/GitHub|password/i);
  });
});
