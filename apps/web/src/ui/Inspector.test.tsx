// Inspector interaction tests verify that host IPv6 intent remains an ordinary
// project edit. Operational state and secret generation stay with their App
// and runtime owners instead of leaking into this presentation component.

// @vitest-environment jsdom

import { createFourRouterReferenceLabV4 } from "@router-simulator/contracts";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Inspector } from "./Inspector";

afterEach(cleanup);

describe("host IPv6 inspector", () => {
  it("submits stable opaque identity intent without exposing its secret", async () => {
    const project = createFourRouterReferenceLabV4();
    const updateHost = vi.fn();
    const user = userEvent.setup();
    render(<Inspector selected="h1" tab="chassis" onTabChange={vi.fn()}
      project={project} updateHost={updateHost} updateRouter={vi.fn()}
      setCard={vi.fn()} setMda={vi.fn()} setCardAdmin={vi.fn()}
      setMdaAdmin={vi.fn()} setLink={vi.fn()} updateLink={vi.fn()}
      deleteLink={vi.fn()} deleteNode={vi.fn()} updateAnnotation={vi.fn()}
      deleteAnnotation={vi.fn()}
      ping={vi.fn().mockResolvedValue("")} width={324}
      onWidthChange={vi.fn()} openConsole={vi.fn()} close={vi.fn()} />);

    await user.selectOptions(screen.getByLabelText(
      "IPv6 interface identifier"), "stable-opaque");
    await user.type(screen.getByLabelText("IPv6 network identity"),
      "access-a");
    await user.click(screen.getByRole("button", { name: "Apply" }));

    expect(updateHost).toHaveBeenCalledOnce();
    const submitted = updateHost.mock.calls[0][0];
    expect(submitted.eth0.ipv6).toMatchObject({
      interfaceIdentifierMode: "stable-opaque",
      networkId: "access-a",
      stableIidSecret: null
    });
    expect(screen.queryByLabelText("Stable IID secret")).toBeNull();
  });
});
