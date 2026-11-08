// Portable IS-IS intent owns explicit leaf presence. Release bounds come from
// generated YANG facts; this contract cannot access runtime or browser state.
import { ISIS_CONFIGURATION_PROFILE as profile } from "./generated-isis-configuration-profile";
export type IsisLevels = "1" | "2" | "1/2";
export interface IsisInterfaceLevelIntent {
  present: boolean;
  metric: number | null;
  helloIntervalSeconds: number | null;
  helloMultiplier: number | null;
  priority: number | null;
  passive: boolean | null;
}
export interface IsisInstanceLevelIntent {
  present: boolean;
  defaultMetric: number | null;
  lspMtuOctets: number | null;
  preference: number | null;
  externalPreference: number | null;
  wideMetricsOnly: boolean | null;
}
export interface IsisInterfaceIntent {
  name: string;
  type: "point-to-point" | "broadcast" | null;
  levelCapability: IsisLevels | null;
  adminEnabled: boolean | null;
  passive: boolean | null;
  csnpIntervalSeconds: number | null;
  retransmitIntervalSeconds: number | null;
  lspPacingIntervalMilliseconds: number | null;
  levels: [IsisInterfaceLevelIntent, IsisInterfaceLevelIntent];
}
export interface IsisWaitTimerIntent {
  maximumMilliseconds: number | null;
  initialMilliseconds: number | null;
  secondMilliseconds: number | null;
}
export interface IsisInstanceIntent {
  instance: number;
  adminEnabled: boolean | null;
  ipv4Routing: boolean | null;
  ipv6Routing: "false" | "native" | "mt" | null;
  levelCapability: IsisLevels | null;
  systemId: string | null;
  routerId: string | null;
  lspLifetimeSeconds: number | null;
  lspMtuOctets: number | null;
  levels: [IsisInstanceLevelIntent, IsisInstanceLevelIntent];
  areas: string[];
  interfaces: IsisInterfaceIntent[];
  advertisePassiveOnly?: boolean | null;
  spfWait?: IsisWaitTimerIntent;
  lspWait?: IsisWaitTimerIntent;
}
export interface RouterIsisIntent { instances: IsisInstanceIntent[] }
const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const shape = (value: unknown, names: string, optional = ""): value is Record<string, unknown> =>
  object(value) && names.split(" ").every((name) => Object.hasOwn(value, name)) &&
  Object.keys(value).every((name) => names.split(" ").includes(name) || (optional.length > 0 && optional.split(" ").includes(name)));
const boolean = (value: unknown) => value === null || typeof value === "boolean";
const enumeration = (value: unknown, values: string[]) => value === null || values.includes(value as string);
const integer = (value: unknown, minimum: number, maximum: number): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= minimum && value <= maximum;
const range = (value: unknown, name: string) => value === null || integer(value,
  profile[(name + "_minimum") as keyof typeof profile] as number,
  profile[(name + "_maximum") as keyof typeof profile] as number);
const dense = <T>(values: T[], predicate: (value: T) => boolean): boolean => {
  for (const value of values) if (!predicate(value)) return false;
  return true;
};
const levelCapability = (value: unknown) => enumeration(value, ["1", "2", "1/2"]);
function areaKey(value: unknown): string | null {
  if (typeof value !== "string" || !/^[a-f0-9]{2}(?:\.(?:[a-f0-9]{4}|[a-f0-9]{2}))*$/i.test(value)) return null;
  const bytes = value.replaceAll(".", "").toLowerCase();
  return bytes.length <= 26 ? bytes : null;
}
function level(value: unknown, parent: boolean): boolean {
  const fields = parent ? "present defaultMetric lspMtuOctets preference externalPreference wideMetricsOnly" :
    "present metric helloIntervalSeconds helloMultiplier priority passive";
  if (!shape(value, fields) || typeof value.present !== "boolean") return false;
  if (!value.present && Object.entries(value).some(([key, field]) => key !== "present" && field !== null)) return false;
  return parent ? range(value.defaultMetric, "default_metric") && range(value.lspMtuOctets, "level_lsp_mtu_octets") &&
    range(value.preference, "preference") && range(value.externalPreference, "external_preference") && boolean(value.wideMetricsOnly) :
    range(value.metric, "metric") && range(value.helloIntervalSeconds, "hello_interval_seconds") &&
    range(value.helloMultiplier, "hello_multiplier") && range(value.priority, "priority") && boolean(value.passive);
}
function interfaceIntent(value: unknown): value is IsisInterfaceIntent {
  if (!shape(value, "name type levelCapability adminEnabled passive csnpIntervalSeconds retransmitIntervalSeconds lspPacingIntervalMilliseconds levels") ||
      typeof value.name !== "string" || !Array.isArray(value.levels) || value.levels.length !== 2) return false;
  const characters = [...value.name];
  return characters.length >= profile.interface_name_minimum && characters.length <= profile.interface_name_maximum &&
    !characters.some((character) => character === "\0" || (character.codePointAt(0)! >= 0xd800 && character.codePointAt(0)! <= 0xdfff)) &&
    enumeration(value.type, ["point-to-point", "broadcast"]) && levelCapability(value.levelCapability) &&
    boolean(value.adminEnabled) && boolean(value.passive) && range(value.csnpIntervalSeconds, "csnp_interval_seconds") &&
    range(value.retransmitIntervalSeconds, "retransmit_interval_seconds") && range(value.lspPacingIntervalMilliseconds, "lsp_pacing_interval_milliseconds") &&
    dense(value.levels, (item) => level(item, false));
}
function waitTimer(value: unknown, kind: "spf" | "lsp"): value is IsisWaitTimerIntent {
  return shape(value, "maximumMilliseconds initialMilliseconds secondMilliseconds") &&
    range(value.maximumMilliseconds, `${kind}_max_wait_milliseconds`) &&
    range(value.initialMilliseconds, `${kind}_initial_wait_milliseconds`) &&
    range(value.secondMilliseconds, `${kind}_second_wait_milliseconds`);
}
function instanceIntent(value: unknown): value is IsisInstanceIntent {
  if (!shape(value, "instance adminEnabled ipv4Routing ipv6Routing levelCapability systemId routerId lspLifetimeSeconds lspMtuOctets levels areas interfaces", "spfWait lspWait advertisePassiveOnly") ||
      !integer(value.instance, profile.instance_minimum, profile.instance_maximum) ||
      (Object.hasOwn(value, "advertisePassiveOnly") && !boolean(value.advertisePassiveOnly)) ||
      !boolean(value.adminEnabled) || !boolean(value.ipv4Routing) || !enumeration(value.ipv6Routing, ["false", "native", "mt"]) ||
      !levelCapability(value.levelCapability) || !range(value.lspLifetimeSeconds, "lsp_lifetime_seconds") || !range(value.lspMtuOctets, "lsp_mtu_octets") ||
      !Array.isArray(value.levels) || value.levels.length !== 2 || !dense(value.levels, (item) => level(item, true)) ||
      !Array.isArray(value.areas) || value.areas.length > profile.area_addresses_maximum || !Array.isArray(value.interfaces) ||
      !dense(value.interfaces, interfaceIntent) ||
      (Object.hasOwn(value, "spfWait") && !waitTimer(value.spfWait, "spf")) ||
      (Object.hasOwn(value, "lspWait") && !waitTimer(value.lspWait, "lsp"))) return false;
  if (value.systemId !== null && (typeof value.systemId !== "string" || !/^[a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4}$/i.test(value.systemId))) return false;
  if (value.routerId !== null && (typeof value.routerId !== "string" ||
      !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value.routerId) || value.routerId.split(".").some((octet) => Number(octet) > 255))) return false;
  const areas = Array.from(value.areas, areaKey);
  return !areas.includes(null) && new Set(areas).size === areas.length &&
    new Set(value.interfaces.map((item) => item.name)).size === value.interfaces.length;
}
export function isRouterIsisIntent(value: unknown): value is RouterIsisIntent {
  return shape(value, "instances") && Array.isArray(value.instances) && dense(value.instances, instanceIntent) &&
    new Set(value.instances.map((item) => item.instance)).size === value.instances.length;
}

// Protocol payload only. The project retains the typed tree above; this fixed
// byte order matches the native intent codec and preserves every absent leaf.
export function encodeIsisConfigurationHex(configuration: RouterIsisIntent): string {
  if (!isRouterIsisIntent(configuration)) throw new TypeError("Invalid IS-IS intent");
  const bytes: number[] = [];
  const number = (value: number, width: number) => {
    for (let index = 0; index < width; index++) { bytes.push(value % 256); value = Math.floor(value / 256); }
  };
  const boolean = (value: boolean) => number(value ? 1 : 0, 1);
  const optional = <T>(value: T | null, write: (entry: T) => void) => { boolean(value !== null); if (value !== null) write(value); };
  const integer = (value: number | null, width: number) => optional(value, (entry) => number(entry, width));
  const levels = (value: IsisLevels | null) => optional(value, (entry) => number(entry === "1/2" ? 3 : Number(entry), 1));
  const vector = <T>(values: T[], write: (entry: T) => void) => { number(values.length, 4); values.forEach(write); };
  const hexBytes = (text: string) => text.match(/../g)!.map((pair) => parseInt(pair, 16));
  const string = (text: string) => { const encoded = new TextEncoder().encode(text); number(encoded.length, 2); bytes.push(...encoded); };
  number(3, 1);
  vector(configuration.instances, (instance) => {
    number(instance.instance, 1); optional(instance.adminEnabled, boolean); optional(instance.ipv4Routing, boolean);
    optional(instance.ipv6Routing, (value) => number(["false", "native", "mt"].indexOf(value), 1)); levels(instance.levelCapability);
    optional(instance.systemId, (value) => bytes.push(...hexBytes(value.replaceAll(".", ""))));
    optional(instance.routerId, (value) => number(value.split(".").reduce((address, octet) => address * 256 + Number(octet), 0), 4));
    integer(instance.lspLifetimeSeconds, 2); integer(instance.lspMtuOctets, 2);
    for (const level of instance.levels) {
      boolean(level.present); integer(level.defaultMetric, 4); integer(level.lspMtuOctets, 2);
      integer(level.preference, 1); integer(level.externalPreference, 1); optional(level.wideMetricsOnly, boolean);
    }
    vector(instance.areas, (value) => { const octets = hexBytes(areaKey(value)!); bytes.push(...octets, ...Array(13 - octets.length).fill(0)); number(octets.length, 1); });
    vector(instance.interfaces, (interfaceIntent) => {
      string(interfaceIntent.name); optional(interfaceIntent.type, (value) => number(value === "point-to-point" ? 0 : 1, 1));
      levels(interfaceIntent.levelCapability); optional(interfaceIntent.adminEnabled, boolean); optional(interfaceIntent.passive, boolean);
      integer(interfaceIntent.csnpIntervalSeconds, 2); integer(interfaceIntent.retransmitIntervalSeconds, 2); integer(interfaceIntent.lspPacingIntervalMilliseconds, 2);
      for (const level of interfaceIntent.levels) {
        boolean(level.present); integer(level.metric, 4); integer(level.helloIntervalSeconds, 2);
        integer(level.helloMultiplier, 1); integer(level.priority, 1); optional(level.passive, boolean);
      }
    });
    for (const timer of [instance.spfWait, instance.lspWait]) {
      integer(timer?.maximumMilliseconds ?? null, 4);
      integer(timer?.initialMilliseconds ?? null, 4);
      integer(timer?.secondMilliseconds ?? null, 4);
    }
    optional(instance.advertisePassiveOnly ?? null, boolean);
  });
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
