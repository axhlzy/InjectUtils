<h1>Embeddings</h1>
<p>The <code>Embeddings</code> class is defined in <code>embeddings.h</code> at <code>liboai::Embeddings</code>, and its interface can ideally be accessed through a <code>liboai::OpenAI</code> object.

This class and its associated <code>liboai::OpenAI</code> interface allow access to the <a href="https://beta.openai.com/docs/api-reference/embeddings">Embeddings</a> endpoint of the OpenAI API; this endpoint's functionality can be found below.</p>
- Get a vector representation of a given input that can be easily consumed by machine learning models and algorithms.

<br>
<h2>Methods</h2>
<p>This document covers the method(s) located in <code>embeddings.h</code>. You can find their function signature(s) below.</p>

<h3>Create an Embedding</h3>
<p>Creates an embedding vector representing the input text. Returns a <code>liboai::Response</code> containing response data.</p>

```cpp
liboai::Response create(
  const std::string& model_id,
  std::optional<std::string> input = std::nullopt,
  std::optional<std::string> user = std::nullopt
) const & noexcept(false);
```

<h3>Create an Embedding (async)</h3>
<p>Asynchronously creates an embedding vector representing the input text. Returns a <code>liboai::FutureResponse</code> containing future response data.</p>

```cpp
liboai::FutureResponse create_async(
  const std::string& model_id,
  std::optional<std::string> input = std::nullopt,
  std::optional<std::string> user = std::nullopt
) const & noexcept(false);
```

<p>All function parameters marked <code>optional</code> are not required and are resolved on OpenAI's end if not supplied.</p>

<br>
<h2>Example Usage</h2>
<p>For example usage of the above function(s), please refer to the <a href="./examples">examples</a> folder.
