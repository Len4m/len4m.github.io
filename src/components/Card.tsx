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
    <li className="my-6 group relative transition-colors duration-300 hover:bg-skin-card hover:bg-opacity-30 rounded-lg p-4 -m-4">
      {/* Enlace invisible que cubre toda la card */}
      <a
        href={href}
        className="absolute inset-0 z-10"
        aria-label={title}
      />
      
      {/* Contenido de la card */}
      <div className="relative z-0">
        {secHeading ? (
          <>
            <h2 {...headerProps} className="text-center text-xl text-skin-accent">
              {title}
            </h2>
            <img
              alt={title}
              src={typeof frontmatter.ogImage === "string" ? `/${frontmatter.ogImage}` : frontmatter.ogImage?.src || `/assets/avatar.png`}
              className="h-auto w-full max-w-lg mx-auto mt-2 mb-4 transition-all duration-300 rounded-lg cursor-pointer filter grayscale opacity-75 group-hover:grayscale-0 group-hover:opacity-100"
            />
          </>
        ) : (
          <h3 {...headerProps} className="text-lg font-medium decoration-dashed hover:underline text-skin-accent">
            {title}
          </h3>
        )}
      <Dateposts
        pubDatetime={pubDatetime}
        modDatetime={modDatetime}
        size="lg"
        className="my-2"
      />
      <p>{description}</p>
      </div>
    </li>
  );
}
