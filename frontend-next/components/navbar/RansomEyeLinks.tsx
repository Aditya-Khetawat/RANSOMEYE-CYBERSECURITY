"use client";

import { Subtitle } from "@tremor/react";
import { LinkWithIcon } from "components/LinkWithIcon";
import { Disclosure } from "@headlessui/react";
import { IoChevronUp } from "react-icons/io5";
import { IconType } from "react-icons/lib";
import clsx from "clsx";
import {
  TbBiohazard,
  TbShieldCheck,
  TbFlask,
  TbLayoutDashboard,
  TbDeviceDesktop,
  TbAlertHexagon,
  TbFingerprint,
  TbRadar2,
  TbShieldLock,
} from "react-icons/tb";

type NavLink = {
  href: string;
  label: string;
  icon: IconType;
  testId: string;
  isExact?: boolean;
  isDemo?: boolean;
  accent?: boolean;
};

type NavSection = {
  title: string;
  links: NavLink[];
};

// The sidebar is the pitch: SEE -> PROVE -> UNDERSTAND -> PREDICT -> STOP.
// Every page has one job in that story; the inherited alert-correlation
// pages (Alerts, Correlations, Dedup, Providers, ...) are intentionally not
// exposed — the backend engine stays, but the judge walks the ransomware
// story, not the inspiration product.
const SECTIONS: NavSection[] = [
  {
    title: "SEE",
    links: [
      { href: "/", label: "Command Center", icon: TbLayoutDashboard, testId: "home", isExact: true },
      { href: "/detection", label: "Ransomware Early Warning", icon: TbBiohazard, testId: "detection" },
      { href: "/fleet", label: "Endpoint Fleet", icon: TbDeviceDesktop, testId: "fleet" },
    ],
  },
  {
    title: "PROVE",
    links: [
      { href: "/lab", label: "Attack Lab", icon: TbFlask, testId: "lab", accent: true },
      { href: "/evaluation", label: "Trust & Evaluation", icon: TbShieldCheck, testId: "evaluation" },
    ],
  },
  {
    title: "UNDERSTAND",
    links: [
      { href: "/incidents", label: "Incidents", icon: TbAlertHexagon, testId: "incidents" },
      { href: "/evidence", label: "Evidence", icon: TbFingerprint, testId: "evidence" },
    ],
  },
  {
    title: "PREDICT",
    links: [{ href: "/blast-radius", label: "Blast Radius", icon: TbRadar2, testId: "blast-radius" }],
  },
  {
    title: "STOP",
    links: [{ href: "/containment", label: "Containment", icon: TbShieldLock, testId: "containment" }],
  },
];

const NavGroup = ({ title, links }: NavSection) => (
  <Disclosure as="div" className="space-y-0.5" defaultOpen>
    <Disclosure.Button className="w-full flex justify-between items-center px-2">
      {({ open }) => (
        <>
          <Subtitle className="text-xs ml-2 text-gray-900 font-medium uppercase">
            {title}
          </Subtitle>
          <IoChevronUp
            className={clsx({ "rotate-180": open }, "mr-2 text-slate-400")}
          />
        </>
      )}
    </Disclosure.Button>
    <Disclosure.Panel as="ul" className="space-y-0.5 p-1 pr-1">
      {links.map((link) => (
        <li key={link.href}>
          <LinkWithIcon
            href={link.href}
            icon={link.icon}
            testId={link.testId}
            isExact={link.isExact}
            isBeta={link.isDemo}
          >
            <Subtitle
              className={clsx(
                "text-xs",
                link.accent && "font-semibold text-orange-600 dark:text-orange-400"
              )}
            >
              {link.label}
              {link.accent && (
                <span className="ml-1.5 rounded bg-orange-100 px-1 py-px text-[9px] font-bold uppercase tracking-wide text-orange-700 dark:bg-orange-950 dark:text-orange-300">
                  Prove it
                </span>
              )}
            </Subtitle>
          </LinkWithIcon>
        </li>
      ))}
    </Disclosure.Panel>
  </Disclosure>
);

export const RansomEyeLinks = () => (
  <>
    {SECTIONS.map((section) => (
      <NavGroup key={section.title} {...section} />
    ))}
  </>
);
