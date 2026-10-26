import type { Response } from "express";

export type PageStatus = "info" | "success" | "warning" | "error";

export interface MessagePage {
  status: PageStatus;
  /** One line saying what happened. */
  heading: string;
  /** What to do next. */
  text: string;
  link?: { href: string; text: string };
}

/** Renders views/message.ejs: one message on a branded page. */
export function renderMessage(res: Response, httpStatus: number, page: MessagePage): void {
  res.status(httpStatus).render("message", { ...page, link: page.link ?? null });
}
