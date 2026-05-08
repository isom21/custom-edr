import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, FlaskConical, Wand2, XCircle } from "lucide-react";
import { sigmaApi, type SigmaCompileResponse, type SigmaTestResponse } from "@/api/sigma";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export function SigmaPanel({
  body,
  ruleId,
  isNew,
}: {
  body: string;
  ruleId?: string;
  isNew: boolean;
}) {
  const [compileResult, setCompileResult] = useState<SigmaCompileResponse | null>(null);
  const [testResult, setTestResult] = useState<SigmaTestResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const compile = useMutation({
    mutationFn: () => sigmaApi.compile(body),
    onSuccess: (r) => {
      setCompileResult(r);
      setError(null);
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail : String(e)),
  });

  const runTest = useMutation({
    mutationFn: () =>
      ruleId && !isNew
        ? sigmaApi.testSavedRule(ruleId, body || null)
        : sigmaApi.testAdhoc(body),
    onSuccess: (r) => {
      setTestResult(r);
      setError(null);
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail : String(e)),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FlaskConical className="h-5 w-5" /> Sigma helpers
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={() => compile.mutate()}
            disabled={!body || compile.isPending}
          >
            <Wand2 className="h-4 w-4" /> Compile
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => runTest.mutate()}
            disabled={!body || runTest.isPending}
          >
            <FlaskConical className="h-4 w-4" />
            {runTest.isPending ? "Running..." : "Test against last 24h"}
          </Button>
        </div>

        {error && (
          <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}

        {compileResult && (
          <div className="space-y-1 rounded-md border p-3 text-sm">
            <div className="flex items-center gap-2">
              {compileResult.ok ? (
                <CheckCircle2 className="h-4 w-4 text-green-600" />
              ) : (
                <XCircle className="h-4 w-4 text-destructive" />
              )}
              <span className="font-medium">
                {compileResult.ok ? "Compiles cleanly" : "Compile error"}
              </span>
            </div>
            {compileResult.error && (
              <div className="text-destructive">{compileResult.error}</div>
            )}
            {compileResult.query && (
              <div>
                <span className="text-muted-foreground">Lucene query: </span>
                <code className="break-all rounded bg-muted px-1 py-0.5 font-mono text-xs">
                  {compileResult.query}
                </code>
              </div>
            )}
            {compileResult.title && (
              <div className="text-muted-foreground">
                Title: <span className="text-foreground">{compileResult.title}</span>
              </div>
            )}
          </div>
        )}

        {testResult && (
          <div className="space-y-2 rounded-md border p-3 text-sm">
            <div className="flex items-center justify-between">
              <span className="font-medium">
                Matches over last 24h:{" "}
                <Badge variant={testResult.total > 0 ? "default" : "outline"}>
                  {testResult.total}
                </Badge>
              </span>
              <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
                {testResult.query}
              </code>
            </div>
            {testResult.samples.length > 0 && (
              <div className="max-h-64 space-y-1 overflow-auto rounded bg-muted/40 p-2 font-mono text-xs">
                {testResult.samples.map((s, i) => (
                  <div key={i} className="border-b border-border/40 pb-1 last:border-0">
                    <div className="text-muted-foreground">{s.timestamp ?? "—"}</div>
                    <div>
                      host=
                      <span className="text-foreground">{s.host_id ?? "—"}</span>{" "}
                      proc=
                      <span className="text-foreground">
                        {(s.process as { name?: string } | null)?.name ?? "—"}
                      </span>{" "}
                      exec=
                      <span className="text-foreground">
                        {(s.process as { executable?: string } | null)?.executable ?? "—"}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
            {testResult.samples.length === 0 && testResult.total === 0 && (
              <div className="text-muted-foreground">No matches in the last 24h.</div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
