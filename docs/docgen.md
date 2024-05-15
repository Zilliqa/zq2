# docgen

Documentation is generated via `z2 doc-gen`.

This:

 * Deletes all subkeys of a given prefix from `mkdocs.yaml`
 * Recurses through the source tree.
 * Locates files called `<prefix>.tera.md`
 * For each such file, splits it (using a regex!) into heading/content pairs.
 * Uses tera to substitute some keys into each section of content, as a separate template (see below)
 * Substitutes the heading/content pairs into a template in `z2/resources/api.tera.md`
 * Spits the result out into a `mkdocs` document tree
 * Rewrites the `mkdocs.yaml` file to include it.

The above rather odd behaviour just happens to be what the `docgen`
program in `zilliqa-developer/products/developer-portal/docgen` needs
in order to download a set of Zilliqa 2 tags and ask them to render
their documentation into the `mkdocs` document heirarchy for display.

In future, `z2 doc-gen` will sense the type of documentation it is
rendering and use different templates (and not assume that all docs
are API docs).

## Sections expected in API documentation

Sections expected in API documentation:

| Section | Required? | Description |
| ------- | --------  | ----------- | 
| Title   | Yes       | How the page will be named as a file and in ids |
| Keywords | Yes      | Contains comma-separated keywords used in the mkdocs search index |
| Description | Yes   | Describes the API call |
| Curl    |  No       | Sample curl call  |
| Response | Yes       | Sample API response |
| Arguments | Yes     | Table of arguments |

## Tera keys provided to API documentation

This section documents the keys you can use in API documentation.

Currently there aren't any.

