import type { CollectionEntry } from "astro:content";
import { getCollection } from "astro:content";

/**
 * Gets the slug for a post, preferring the urlSlug from frontmatter
 * over the file-based slug. This allows posts to have different
 * slugs in different languages for better SEO.
 */
export function getPostSlug(post: CollectionEntry<"blog">): string {
  return post.data.urlSlug || post.slug;
}

/**
 * Finds a related post in a different language by translationId.
 * If translationId is not set, returns null.
 */
export async function getRelatedPost(
  currentPost: CollectionEntry<"blog">,
  targetLang: string
): Promise<CollectionEntry<"blog"> | null> {
  if (!currentPost.data.translationId) {
    return null;
  }

  const allPosts = await getCollection("blog", ({ data }) => 
    !data.draft && 
    data.lang === targetLang &&
    data.translationId === currentPost.data.translationId
  );

  return allPosts[0] || null;
}

/**
 * Gets the URL for a post in a specific language.
 * If a related post exists, uses its slug. Otherwise, returns null.
 */
export async function getPostUrlInLanguage(
  currentPost: CollectionEntry<"blog">,
  targetLang: string
): Promise<string | null> {
  const relatedPost = await getRelatedPost(currentPost, targetLang);
  
  if (!relatedPost) {
    return null;
  }

  const slug = getPostSlug(relatedPost);
  const langPrefix = targetLang !== 'en' ? `/${targetLang}` : '';
  
  return `${langPrefix}/posts/${slug}/`;
}

