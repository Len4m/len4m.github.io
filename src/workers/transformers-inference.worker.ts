import {
  AutoModelForCausalLM,
  AutoTokenizer,
  TextStreamer,
} from "@huggingface/transformers";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let model: any = null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let tokenizer: any = null;
let currentModelId: string | null = null;
let currentDevice: string = "wasm";

type ChatMessage = { role: "system" | "user" | "assistant"; content: string };

self.onmessage = async (
  e: MessageEvent<{
    type: string;
    modelId?: string;
    device?: string;
    dtype?: string;
    messages?: ChatMessage[];
    max_new_tokens?: number;
  }>
) => {
  const { type, modelId, device, dtype, messages, max_new_tokens = 256 } =
    e.data ?? {};

  if (type === "load" && modelId) {
    try {
      if (currentModelId !== modelId) {
        model = null;
        tokenizer = null;
        currentModelId = null;
      }

      const dev = device ?? "wasm";
      currentDevice = dev;

      const progressCb = (info: {
        status?: string;
        progress?: number;
        file?: string;
      }) => {
        self.postMessage({
          type: "progress",
          status: info.status,
          progress: info.progress,
          file: info.file,
        });
      };

      tokenizer = await AutoTokenizer.from_pretrained(modelId, {
        progress_callback: progressCb,
      });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const modelOpts: Record<string, any> = {
        dtype: dtype ?? "q4",
        device: dev,
        progress_callback: progressCb,
      };

      model = await AutoModelForCausalLM.from_pretrained(modelId, modelOpts);

      if (dev === "webgpu") {
        self.postMessage({
          type: "progress",
          status: "progress",
          progress: 100,
          file: "Compilando shaders GPU…",
        });
        await model.generate({
          ...tokenizer("warmup"),
          max_new_tokens: 1,
        });
      }

      currentModelId = modelId;
      self.postMessage({ type: "ready" });
    } catch (err) {
      self.postMessage({
        type: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
    return;
  }

  if (type === "generate" && model && tokenizer && messages) {
    try {
      const inputs = tokenizer.apply_chat_template(messages, {
        add_generation_prompt: true,
        return_dict: true,
      });

      const streamer = new TextStreamer(tokenizer, {
        skip_prompt: true,
        skip_special_tokens: true,
        callback_function: (text: string) => {
          if (text.length > 0) self.postMessage({ type: "chunk", text });
        },
      });

      // do_sample: true can be buggy on WebGPU (topk sampling issue)
      const samplingOpts =
        currentDevice === "webgpu"
          ? { do_sample: false }
          : { do_sample: true, temperature: 0.6, top_p: 0.9 };

      await model.generate({
        ...inputs,
        max_new_tokens,
        ...samplingOpts,
        streamer,
      });

      self.postMessage({ type: "done" });
    } catch (err) {
      self.postMessage({
        type: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }
};
