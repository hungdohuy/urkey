import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";
import { fakeClient } from "./test-fake-client";

describe("onboarding", () => {
  it("offers create, sign in and recovery", async () => {
    render(<App client={fakeClient()} />);
    expect(await screen.findByRole("button", { name: "Create a new vault" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in on this device" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Use a Recovery Key" })).toBeInTheDocument();
  });

  it("creates a vault and holds the Emergency Kit until confirmed", async () => {
    render(<App client={fakeClient()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Create a new vault" }));
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "a@example.test" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    fireEvent.change(screen.getByLabelText("Master password"), { target: { value: "correct horse battery" } });
    fireEvent.change(screen.getByLabelText("Repeat master password"), { target: { value: "correct horse battery" } });
    fireEvent.click(screen.getByRole("button", { name: "Create vault" }));
    const kit = await screen.findByRole("region", { name: "Emergency Kit" });
    expect(within(kit).getByTestId("kit-recovery-key").textContent).toMatch(/^UKR1-/);
    const open = screen.getByRole("button", { name: "Open my vault" });
    expect(open).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/last 4 characters/), { target: { value: "PQRS" } });
    expect(open).toBeDisabled(); // wrong
    fireEvent.change(screen.getByLabelText(/last 4 characters/), { target: { value: "qrs7" } });
    fireEvent.click(open);
    expect(await screen.findByText("Your vault is empty")).toBeInTheDocument();
  });
});

describe("lock screen", () => {
  it("shows one generic message for a wrong password", async () => {
    render(<App client={fakeClient({ phase: "locked", email: "a@example.test" })} />);
    fireEvent.change(await screen.findByLabelText("Master password"), { target: { value: "nope" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't unlock. Check your master password");
  });
});

describe("vault", () => {
  async function unlockedWithLogin() {
    const client = fakeClient({ phase: "unlocked", email: "a@example.test" });
    client.items.set("item1", { schema: 1, type: "login", title: "Example", tags: ["work"], notes: "", fields: { username: "alice", password: "s3cret!", urls: [{ url: "https://example.com", label: "website" }] } });
    render(<App client={client} />);
    await screen.findByRole("option", { name: /Example/ });
    return client;
  }

  it("lists items and masks the password until revealed", async () => {
    await unlockedWithLogin();
    fireEvent.click(screen.getByRole("option", { name: /Example/ }));
    expect(await screen.findByRole("heading", { name: "Example" })).toBeInTheDocument();
    expect(screen.getByLabelText("Password, hidden")).toHaveTextContent("••••••••");
    expect(screen.queryByText("s3cret!")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Reveal password" }));
    await waitFor(() => expect(screen.getByText("3").closest("span")?.parentElement?.textContent).toBe("s3cret!"));
  });

  it("filters by search and focuses search with /", async () => {
    await unlockedWithLogin();
    fireEvent.keyDown(window, { key: "/" });
    await waitFor(() => expect(screen.getByLabelText("Search vault")).toHaveFocus());
    fireEvent.change(screen.getByLabelText("Search vault"), { target: { value: "nomatch" } });
    expect(screen.getByText('No items match "nomatch"')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Search vault"), { target: { value: "alice" } });
    expect(screen.getByRole("option", { name: /Example/ })).toBeInTheDocument();
  });

  it("creates a login with a generated password", async () => {
    const client = await unlockedWithLogin();
    fireEvent.keyDown(window, { key: "n" });
    fireEvent.change(await screen.findByLabelText("Title"), { target: { value: "New site" } });
    fireEvent.click(screen.getByRole("button", { name: "Generate a password" }));
    fireEvent.click(await screen.findByRole("button", { name: "Use" }));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect([...client.items.values()].some((i) => i.title === "New site" && i.fields["password"] === "Gen3rated-Passw0rd!")).toBe(true));
  });

  it("keeps the document title generic", async () => {
    await unlockedWithLogin();
    expect(document.title).toBe("urkey");
    expect(document.title).not.toMatch(/Example/);
  });
});
