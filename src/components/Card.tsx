import { slugifyStr } from "@utils/slugify";
// import Datetime from "./Datetime";
import type { CollectionEntry } from "astro:content";
import Dateposts from "./Dateposts";

export interface Props {
  href?: string;
  frontmatter: CollectionEntry<"blog">["data"];
  secHeading?: boolean;
}

export default function Card({ href, frontmatter, secHeading = true }: Props) {
  const { title, description, pubDatetime, modDatetime } = frontmatter;

  const headerProps = {
    style: { viewTransitionName: slugifyStr(title) },
    className: secHeading ? 'text-center text-xl' : '' + "text-lg font-medium decoration-dashed hover:underline",
  };



  return (
    <li className="my-6">
      <a
        href={href}
        className={`${secHeading ? 'text-center ' : ''} block text-lg font-medium text-skin-accent decoration-dashed underline-offset-4 focus-visible:no-underline focus-visible:underline-offset-0`}
      >
        {secHeading ? (
          <>
            <h2  {...headerProps}>{title}</h2>
            <img
              alt={title}
              src={typeof frontmatter.ogImage === "string" ? `/${frontmatter.ogImage}` : frontmatter.ogImage?.src || `/assets/avatar.png`}
              className="h-auto w-full max-w-lg mx-auto mt-2 mb-4 transition-all duration-300 rounded-lg cursor-pointer filter grayscale opacity-75 hover:grayscale-0 hover:opacity-100"
            />
          </>
        ) : (
          <h3 {...headerProps}>{title}</h3>
        )}
      </a>
      <Dateposts
        pubDatetime={pubDatetime}
        modDatetime={modDatetime}
        size="lg"
        className="my-2"
      />
      <p>{description}</p>
    </li>
  );
}
