# docgen

Documentation is generated via `z2 doc-gen`.

This:

 * Deletes all subkeys of a given prefix from `mkdocs.yaml`
 * Recurses through the source tree.
 * Locates files called `<prefix>.doc.md`
 * Sorts that list by relative path (to get a consistent order of documentation pages).
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

If we detect that a method is documented but not implemented, we will
implicitly change its status to `NotYetImplemented`.

One day we could (and should!) generate boilerplate for undocumented methods.
For now, it's hard to tell which section these should go in and so we skip this.


## Sections expected in API documentation

Sections expected in API documentation:

| Section | Required? | Description |
| ------- | --------  | ----------- | 
| Title   | Yes       | How the page will be named as a file and in ids |
| Keywords | Yes      | Contains comma-separated keywords used in the mkdocs search index |
| Description | Yes   | Describes the API call |
| Curl    |  No       | Sample curl call  |
| Nodejs  |  No       | Sample nodejs call |
| Java    |  No       | Sample Java call |
| Python  |  No       | Sample Python call |
| Go      |  No       | Sample Golang call |
| Rust    |  No       | Sample Rust call   | 
| Response | Yes       | Sample API response |
| Arguments | Yes     | Table of arguments |
| Status | No   |  See below |

Note that some sections (specifically `curl` are implicitly indented to 4 characters to make tabs work.

When a section is made into a key, it is lowercased, so that you don't have problems with autocapitalisation in your editor - so the heading `TiTLE` will turn up as the Tera key `title` in your template.

### Status

You can signal the status of an API with the status section:

 * If the status section does not exist, we assume this API is fully implemented - ie. status `Implemented`.
 * `Implemented` means that the API is implemented and documented.
 * `NotYetImplemented` means this API is not yet implemented - an admonition will be printed in the docs.
 * `NeverImplemented` means this API will never be implemented - documentation is here as a convenience.
 * `PartiallyImplemented` means this API is not finished yet - an admonition will be printed in the docs.
 * `NotYetDocumented` means that the API is implemented (though it may not be finished yet), but the docs are to be written.
 * Any other content is treated as `PartiallyImplemented` and the contents of the header become the admonition.

## Tera keys provided to API documentation

This section documents the keys you can use in API documentation.

|    Key    |   Value   |
| --------- | --------- |
| `_api_url` | The RPC API endpoint to synthesise examples for |


