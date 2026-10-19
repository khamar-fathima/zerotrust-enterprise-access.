export default function Pagination({ page, limit, total, totalPages, loading, onPage, onLimit }) {
  const first = total ? (page - 1) * limit + 1 : 0;
  const last = Math.min(page * limit, total);
  return <nav aria-label="List pagination" className="toolbar" style={{ padding: 16, flexWrap: "wrap" }}>
    <span className="panel-note" aria-live="polite">{loading ? "Loading records…" : `${first}–${last} of ${total} · Page ${totalPages ? page : 0} of ${totalPages}`}</span>
    <label className="panel-note">Rows per page{" "}
      <select className="select" aria-label="Rows per page" value={limit} onChange={(event) => onLimit(Number(event.target.value))}>
        {[10, 25, 50, 100].map((size) => <option key={size} value={size}>{size}</option>)}
      </select>
    </label>
    <button className="btn btn-outline" disabled={loading || page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
    <button className="btn btn-outline" disabled={loading || page >= totalPages} onClick={() => onPage(page + 1)}>Next</button>
  </nav>;
}
