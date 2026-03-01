import { useState, useRef, useEffect, useCallback } from "react";
import { Streamdown } from "streamdown";
import "streamdown/styles.css";

type ChatMessage = { role: "system" | "user" | "assistant"; content: string };
type Lang = "es" | "ca" | "en";

interface Translations {
  selectModel: string;
  inference: string;
  download: string;
  recommended: string;
  downloadModel: string;
  retry: string;
  downloadingModel: string;
  downloadingFile: (file: string) => string;
  initiatingFile: (file: string) => string;
  preparingDownload: string;
  loadingModel: string;
  loadError: string;
  unknownError: string;
  chatPlaceholder: string;
  inputPlaceholder: string;
  you: string;
  model: string;
  thinking: string;
  restarting: string;
  send: string;
  stop: string;
}

const I18N: Record<Lang, Translations> = {
  es: {
    selectModel: "Selecciona un modelo y descárgalo en el navegador para chatear.",
    inference: "Inferencia:",
    download: "Descarga:",
    recommended: "recomendada:",
    downloadModel: "Descargar modelo",
    retry: "Reintentar",
    downloadingModel: "Descargando modelo…",
    downloadingFile: (f) => `Descargando ${f}…`,
    initiatingFile: (f) => `Iniciando ${f}…`,
    preparingDownload: "Preparando descarga…",
    loadingModel: "Cargando modelo…",
    loadError: "Error al cargar el modelo",
    unknownError: "Error desconocido",
    chatPlaceholder: "Escribe un mensaje para empezar.",
    inputPlaceholder: "Escribe un mensaje…",
    you: "Tú",
    model: "Modelo",
    thinking: "Pensando…",
    restarting: "Reiniciando modelo…",
    send: "Enviar",
    stop: "Stop",
  },
  ca: {
    selectModel: "Selecciona un model i descarrega'l al navegador per xatejar.",
    inference: "Inferència:",
    download: "Descàrrega:",
    recommended: "recomanada:",
    downloadModel: "Descarregar model",
    retry: "Reintentar",
    downloadingModel: "Descarregant model…",
    downloadingFile: (f) => `Descarregant ${f}…`,
    initiatingFile: (f) => `Iniciant ${f}…`,
    preparingDownload: "Preparant descàrrega…",
    loadingModel: "Carregant model…",
    loadError: "Error en carregar el model",
    unknownError: "Error desconegut",
    chatPlaceholder: "Escriu un missatge per començar.",
    inputPlaceholder: "Escriu un missatge…",
    you: "Tu",
    model: "Model",
    thinking: "Pensant…",
    restarting: "Reiniciant model…",
    send: "Enviar",
    stop: "Stop",
  },
  en: {
    selectModel: "Select a model and download it to the browser to start chatting.",
    inference: "Inference:",
    download: "Download:",
    recommended: "recommended:",
    downloadModel: "Download model",
    retry: "Retry",
    downloadingModel: "Downloading model…",
    downloadingFile: (f) => `Downloading ${f}…`,
    initiatingFile: (f) => `Initiating ${f}…`,
    preparingDownload: "Preparing download…",
    loadingModel: "Loading model…",
    loadError: "Error loading model",
    unknownError: "Unknown error",
    chatPlaceholder: "Type a message to get started.",
    inputPlaceholder: "Type a message…",
    you: "You",
    model: "Model",
    thinking: "Thinking…",
    restarting: "Restarting model…",
    send: "Send",
    stop: "Stop",
  },
};

const SYSTEM_PROMPT: ChatMessage = {
  role: "system",
  content:
    "You are a helpful, concise assistant. Reply in the same language the user writes in. Use Markdown formatting when appropriate.",
};

interface ModelOption {
  id: string;
  label: string;
  downloadSize: string;
  ramRequired: string;
  dtype: string;
  requiresWebGPU?: boolean;
}

const MODELS: ModelOption[] = [
  {
    id: "HuggingFaceTB/SmolLM2-135M-Instruct",
    label: "SmolLM2 135M",
    downloadSize: "182 MB",
    ramRequired: "~512 MB",
    dtype: "q4",
  },
  {
    id: "HuggingFaceTB/SmolLM2-360M-Instruct",
    label: "SmolLM2 360M",
    downloadSize: "388 MB",
    ramRequired: "~1 GB",
    dtype: "q4",
  },
  {
    id: "onnx-community/Llama-3.2-1B-Instruct-ONNX",
    label: "Llama 3.2 1B",
    downloadSize: "1.7 GB",
    ramRequired: "~3 GB VRAM",
    dtype: "q4",
    requiresWebGPU: true,
  },
];

function createWorker() {
  return new Worker(
    new URL(
      "../../workers/transformers-inference.worker.ts",
      import.meta.url
    ),
    { type: "module" }
  );
}

async function checkWebGPU(): Promise<boolean> {
  if (typeof navigator === "undefined" || !("gpu" in navigator)) return false;
  try {
    const gpu = (navigator as unknown as { gpu: { requestAdapter(): Promise<unknown | null> } }).gpu;
    const adapter = await gpu.requestAdapter();
    return adapter !== null;
  } catch {
    return false;
  }
}

export default function Chat({ lang = "es" }: { lang?: Lang }) {
  const t = I18N[lang] ?? I18N.es;

  const [status, setStatus] = useState<
    "idle" | "loading" | "ready" | "error" | "reloading"
  >("idle");
  const [hasWebGPU, setHasWebGPU] = useState<boolean | null>(null);
  const [selectedModel, setSelectedModel] = useState(MODELS[0].id);
  const [progress, setProgress] = useState(0);
  const [progressLabel, setProgressLabel] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const workerRef = useRef<Worker | null>(null);
  const chatBoxRef = useRef<HTMLDivElement>(null);
  const statusRef = useRef(status);
  statusRef.current = status;
  const activeModelRef = useRef<string | null>(null);
  const hasWebGPURef = useRef(false);

  useEffect(() => {
    checkWebGPU().then((v) => {
      setHasWebGPU(v);
      hasWebGPURef.current = v;
    });
  }, []);

  const availableModels = MODELS.filter(
    (m) => !m.requiresWebGPU || hasWebGPU
  );

  useEffect(() => {
    const box = chatBoxRef.current;
    if (box) box.scrollTop = box.scrollHeight;
  }, [messages]);

  const attachWorkerHandlers = useCallback((worker: Worker) => {
    worker.onmessage = (e: MessageEvent) => {
      const d = e.data as {
        type: string;
        text?: string;
        message?: string;
        progress?: number;
        file?: string;
        status?: string;
      };

      switch (d.type) {
        case "progress":
          if (d.status === "progress" && typeof d.progress === "number") {
            setProgress(d.progress);
            setProgressLabel(
              d.file ? t.downloadingFile(d.file) : t.downloadingModel
            );
          } else if (d.file) {
            setProgressLabel(
              d.status === "initiate"
                ? t.initiatingFile(d.file)
                : t.downloadingFile(d.file)
            );
          }
          break;

        case "ready":
          setProgress(100);
          setProgressLabel("");
          setStatus("ready");
          break;

        case "error":
          if (
            statusRef.current === "loading" ||
            statusRef.current === "reloading"
          ) {
            setStatus("error");
            setProgressLabel(d.message ?? t.loadError);
          } else {
            setMessages((prev) => {
              const next = [...prev];
              const last = next[next.length - 1];
              if (last?.role === "assistant")
                next[next.length - 1] = {
                  ...last,
                  content: `Error: ${d.message ?? t.unknownError}`,
                };
              return next;
            });
            setIsGenerating(false);
          }
          break;

        case "chunk":
          if (d.text) {
            setMessages((prev) => {
              const next = [...prev];
              const last = next[next.length - 1];
              if (last?.role === "assistant")
                next[next.length - 1] = {
                  ...last,
                  content: last.content + d.text,
                };
              return next;
            });
          }
          break;

        case "done":
          setIsGenerating(false);
          break;
      }
    };
  }, [t]);

  const loadModel = useCallback(
    (modelId: string) => {
      const modelCfg = MODELS.find((m) => m.id === modelId);
      if (!modelCfg) return;
      if (!workerRef.current) {
        workerRef.current = createWorker();
        attachWorkerHandlers(workerRef.current);
      }
      activeModelRef.current = modelId;
      workerRef.current.postMessage({
        type: "load",
        modelId,
        device: hasWebGPURef.current ? "webgpu" : "wasm",
        dtype: modelCfg.dtype,
      });
    },
    [attachWorkerHandlers]
  );

  const handleDownload = useCallback(() => {
    setStatus("loading");
    setProgress(0);
    setProgressLabel(t.preparingDownload);
    loadModel(selectedModel);
  }, [selectedModel, loadModel, t]);

  const handleSend = useCallback(() => {
    const text = input.trim();
    if (!text || status !== "ready" || !workerRef.current || isGenerating)
      return;

    const userMsg: ChatMessage = { role: "user", content: text };
    const assistantMsg: ChatMessage = { role: "assistant", content: "" };

    setMessages((prev) => {
      const next = [...prev, userMsg, assistantMsg];
      const chatHistory: ChatMessage[] = [
        SYSTEM_PROMPT,
        ...next.filter((m) => m.content.length > 0),
      ];
      workerRef.current!.postMessage({
        type: "generate",
        messages: chatHistory,
        max_new_tokens: 512,
      });
      return next;
    });
    setInput("");
    setIsGenerating(true);
  }, [input, status, isGenerating]);

  const handleStop = useCallback(() => {
    workerRef.current?.terminate();
    workerRef.current = null;
    setIsGenerating(false);
    setStatus("reloading");

    const worker = createWorker();
    attachWorkerHandlers(worker);
    workerRef.current = worker;
    const activeModel = MODELS.find(
      (m) => m.id === activeModelRef.current
    );
    if (activeModel) {
      worker.postMessage({
        type: "load",
        modelId: activeModel.id,
        device: hasWebGPURef.current ? "webgpu" : "wasm",
        dtype: activeModel.dtype,
      });
    }
  }, [attachWorkerHandlers]);

  const handleChangeModel = useCallback(
    (newModelId: string) => {
      if (newModelId === activeModelRef.current || isGenerating) return;
      setSelectedModel(newModelId);
      workerRef.current?.terminate();
      workerRef.current = null;
      setMessages([]);
      setStatus("loading");
      setProgress(0);
      setProgressLabel(t.loadingModel);
      loadModel(newModelId);
    },
    [isGenerating, loadModel, t]
  );

  const currentModelInfo = availableModels.find((m) => m.id === selectedModel);

  if (status === "idle" || status === "error") {
    return (
      <div
        className={`chat-download-section${status === "error" ? " chat-error" : ""}`}
      >
        {status === "error" ? (
          <p className="chat-download-text">{progressLabel}</p>
        ) : (
          <>
            <p className="chat-download-text">{t.selectModel}</p>
            {hasWebGPU !== null && (
              <p className="chat-backend-info">
                {t.inference}{" "}
                {hasWebGPU ? (
                  <strong>
                    <span className="chat-webgpu-badge">WebGPU</span> GPU
                  </strong>
                ) : (
                  <strong>WASM (CPU)</strong>
                )}
              </p>
            )}
            <div className="chat-model-selector">
              <select
                className="chat-select"
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
              >
                {availableModels.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.label} — {m.downloadSize}
                    {m.requiresWebGPU ? " (WebGPU)" : ""}
                  </option>
                ))}
              </select>
              {currentModelInfo && (
                <p className="chat-model-info">
                  {t.download} <strong>{currentModelInfo.downloadSize}</strong>
                  {" · "}
                  {currentModelInfo.requiresWebGPU ? "VRAM" : "RAM"}
                  {" "}{t.recommended}{" "}
                  <strong>{currentModelInfo.ramRequired}</strong>
                  {currentModelInfo.requiresWebGPU && (
                    <span className="chat-webgpu-badge">WebGPU</span>
                  )}
                </p>
              )}
            </div>
          </>
        )}
        <button
          type="button"
          className="chat-download-btn"
          onClick={handleDownload}
        >
          {status === "error" ? t.retry : t.downloadModel}
        </button>
      </div>
    );
  }

  if (status === "loading") {
    return (
      <div className="chat-download-section">
        <p className="chat-download-text">
          {progressLabel || t.downloadingModel}
        </p>
        <div className="chat-progress-track">
          <div
            className="chat-progress-fill"
            style={{ width: `${progress}%` }}
          />
        </div>
        <p className="chat-progress-percent">{Math.round(progress)} %</p>
      </div>
    );
  }

  const displayMessages = messages.filter(
    (m) => m.role === "user" || m.role === "assistant"
  );

  const activeModel = MODELS.find((m) => m.id === activeModelRef.current);
  const usingWebGPU = hasWebGPU && activeModel !== undefined;

  return (
    <div className="chat-container">
      <div className="chat-model-badge">
        <select
          className="chat-model-switch"
          value={selectedModel}
          onChange={(e) => handleChangeModel(e.target.value)}
          disabled={isGenerating || status === "reloading"}
        >
          {availableModels.map((m) => (
            <option key={m.id} value={m.id}>
              {m.label}
              {m.requiresWebGPU ? " (WebGPU)" : ""}
            </option>
          ))}
        </select>
        {usingWebGPU && <span className="chat-webgpu-badge">WebGPU</span>}
      </div>
      <div className="chat-messages" ref={chatBoxRef}>
        {displayMessages.length === 0 && (
          <p className="chat-placeholder">{t.chatPlaceholder}</p>
        )}
        {displayMessages.map((msg, i) => (
          <div key={i} className={`chat-msg chat-msg-${msg.role}`}>
            <span className="chat-msg-role">
              {msg.role === "user" ? t.you : t.model}
            </span>
            {msg.role === "assistant" ? (
              <div className="chat-msg-content chat-markdown">
                {msg.content ? (
                  <Streamdown
                    isAnimating={
                      isGenerating && i === displayMessages.length - 1
                    }
                  >
                    {msg.content}
                  </Streamdown>
                ) : isGenerating && i === displayMessages.length - 1 ? (
                  <div className="chat-typing">
                    <span className="chat-spinner" aria-hidden="true" />
                    <span>{t.thinking}</span>
                  </div>
                ) : null}
              </div>
            ) : (
              <p className="chat-msg-content">{msg.content}</p>
            )}
          </div>
        ))}
      </div>
      <div className="chat-input-row">
        {status === "reloading" && (
          <div className="chat-reloading">
            <span className="chat-spinner" aria-hidden="true" />
            <span>{t.restarting}</span>
          </div>
        )}
        {status !== "reloading" && (
          <>
            <input
              type="text"
              className="chat-input"
              placeholder={t.inputPlaceholder}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  handleSend();
                }
              }}
              disabled={isGenerating}
            />
            {isGenerating ? (
              <button
                type="button"
                className="chat-send-btn chat-stop-btn"
                onClick={handleStop}
              >
                {t.stop}
              </button>
            ) : (
              <button
                type="button"
                className="chat-send-btn"
                onClick={handleSend}
                disabled={!input.trim()}
              >
                {t.send}
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}
