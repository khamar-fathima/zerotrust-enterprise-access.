import { useCallback, useEffect, useState } from "react";
import { errorMessage, safeArray } from "../lib/identity.js";

export default function useRemote(load, deps = []) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setRows(safeArray(await load()));
    } catch (err) {
      setError(errorMessage(err, "The requested records could not be loaded."));
    } finally {
      setLoading(false);
    }
  // Callers provide dependencies for their loader explicitly.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { refresh(); }, [refresh]);
  return { rows, setRows, loading, error, refresh, setError };
}
