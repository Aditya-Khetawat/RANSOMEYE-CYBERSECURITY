"use client";

import { Subtitle } from "@tremor/react";
import { LinkWithIcon } from "components/LinkWithIcon";
import { Disclosure } from "@headlessui/react";
import { IoChevronUp } from "react-icons/io5";
import { IconType } from "react-icons/lib";
import clsx from "clsx";
import { TbBiohazard, TbShieldCheck } from "react-icons/tb";

type NavLink = {
  href: string;
  label: string;
  icon: IconType;
  testId: string;
  isExact?: boolean;
  isDemo?: boolean;
};

type NavSection = {
  title: string;
  links: NavLink[];
};

// RansomEye is a single-purpose product (ransomware early warning) — the
// alert-correlation engine's own multi-section sidebar (Alerts, Incidents,
// Noise Reduction, Insights, Platform) was the *inspiration* codebase's
// navigation, not this product's. Removed along with the frontend page
// routes and UI components it pointed to. The backend engine itself
// (backend/app/*.py) stays — RansomEye's detection core reuses its LLM
// plumbing internally (see backend/app/ransomeye/assistant_bridge.py) — but
// none of it is exposed as separate user-facing pages any more.
const SECTIONS: NavSection[] = [
  {
    title: "OVERVIEW",
    links: [
      {
        href: "/",
        label: "Ransomware Early Warning",
        icon: TbBiohazard,
        testId: "home",
        isExact: true,
      },
      {
        href: "/evaluation",
        label: "Can We Trust It?",
        icon: TbShieldCheck,
        testId: "evaluation",
      },
    ],
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
            <Subtitle className="text-xs">{link.label}</Subtitle>
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
