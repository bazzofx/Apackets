# Images

The pictures this capture carried in the clear: every image carved out of an unencrypted
response body, drawn as a gallery from the stored bytes.

Reachable at `/images`, in the left-hand navigation under **Investigate**, directly after
**Files and Objects**. The component is `frontend/src/pages/ImagesPage.tsx`; the objects it reads
are described in [Files-and-Objects.md](Files-and-Objects.md) and the extraction that produces
them runs in `backend/app/services/object_extractor.py`.

---

## 1. What it answers

[Files and Objects](Files-and-Objects.md) is a ledger of every carved file — certificates,
JSON, HTML, binaries, images — with hashes and sizes. That is the right page for "what came out
of this capture", and the wrong one for "did anything visible come across". This page is the
one question: **which pictures did this capture show**, drawn.

## 2. Where the images come from, and where they do not

* **Unencrypted bodies only.** The extraction stage carves HTTP response bodies today; other
  cleartext protocols will appear here as their extractors do. The page reads
  `objects` and nothing else.
* **TLS is never decrypted**, so an image behind HTTPS is not here and cannot be. That is not a
  limit of this page; it is the local-only, no-decryption design of the whole application.
* **A type is not required.** Carved bodies frequently record `application/octet-stream` or no
  type at all, so an object counts as an image when its recorded type says `image/` *or*
  its file name ends in a raster suffix (`.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`,
  `.webp`, `.tif`, `.tiff`, `.ico`, `.avif`).
* **SVG is deliberately excluded.** An SVG is a document that can carry script; it is listed on
  Files and Objects like any other file, and it is never drawn or offered to the gallery.

## 3. The two requests

| Action | Call |
|---|---|
| List the images | `GET /api/analyses/{id}/objects?content_type=image&page_size=120[&search=]` |
| Draw one | `GET /api/analyses/{id}/objects/{object_id}/export?inline=1` |
| Download one | `GET /api/analyses/{id}/objects/{object_id}/export` |

**Inline is a privilege, not a request.** The export route decides the media type itself: the
recorded content type is used when it is a raster image type, otherwise the file-name suffix
is; anything that is not a raster image is returned as an attachment whatever the query string
says. Every response keeps `X-Content-Type-Options: nosniff`, inline images are cached for an
hour (`private, max-age=3600`) because a gallery re-reads the same handful of pictures, and
attachments stay `no-store`.

## 4. The page

* A **grid** of cards (1–4 columns by width), each with the image, its file name, size, the
  protocol it came from, the endpoint pair, and two actions: **Download** and **Details** (which
  opens the same object on Files and Objects, filtered to its name).
* **A card that cannot be drawn says so** rather than showing a broken image: a body whose bytes
  this browser will not decode is reported with its recorded type, and remains downloadable.
* **A name filter**, applied server-side, so it works over the whole object set rather than the
  page on screen.
* **An honest empty state**: when nothing was extracted it says the stage found no picture in a
  cleartext body, and points at Files and Objects, whose **Extract** button can re-run the stage.

## 5. Limits and honest caveats

* **Only what the extractor carved.** A picture downloaded over TLS, or one HTTP body TShark
  did not export, is not here — and the page cannot know it existed.
* **A name is evidence, not proof.** A body called `photo.png` that is not a PNG will be
  offered to the browser and fail to draw; the card says so. The alternative — rendering
  unknown bytes as if they were pictures — is worse.
* **No previews are generated.** The thumbnail *is* the stored file, scaled by the browser, so
  a 20 MB image costs 20 MB the first time it is drawn and nothing afterwards (it is cached).
* **`page_size=120`** caps the grid; the subtitle reports when there are more, and the name
  filter is how you reach the rest.
* **The list is not a timeline.** Objects carry no capture timestamp in this build, so cards
  cannot be ordered by when they crossed the wire.

## 6. Related

[Files-and-Objects.md](Files-and-Objects.md) is the ledger this page filters, and its **Extract**
button is what fills both. [HTTP](HTTP.md) shows the transactions the bodies came from, and
[Architecture.md](Architecture.md) §3 describes the extraction stage itself. The endpoint
parameters are in [`docs/CONTRACT.md`](../docs/CONTRACT.md) §5.
