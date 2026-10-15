// Start both requests together, but render each section as soon as it is ready.
export async function loadAnalyticsSections(loadSummary, loadSettings, renderSummary, renderSettings) {
  await Promise.all([
    loadSummary().then(renderSummary),
    loadSettings().then(renderSettings)
  ]);
}
