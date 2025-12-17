import os, requests, json, sys, time

# PDF generation
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4


# -----------------------------
# CONFIGURATION
# -----------------------------
SONAR_URL = os.getenv("SONAR_URL", "http://192.168.119.128:9090")
SONAR_TOKEN = os.getenv("SONAR_TOKEN", "squ_336b97342ccf4127ad9b05275f07c24035cd8d01")
PROJECT_KEY = os.getenv("PROJECT_KEY", "Tic_toc")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_API = f"{OLLAMA_HOST}/api/generate"
MODEL = os.getenv("OLLAMA_MODEL", "gemma3:latest")


# -----------------------------
# VALIDATE ENV
# -----------------------------
def require_env(varname, value):
    if not value:
        print(f"❌ Missing environment variable: {varname}")
        sys.exit(1)

require_env("SONAR_TOKEN", SONAR_TOKEN)
require_env("PROJECT_KEY", PROJECT_KEY)


# -----------------------------
# FETCH SECURITY HOTSPOTS
# -----------------------------
def fetch_sonar_hotspots():
    url = f"{SONAR_URL}/api/hotspots/search?projectKey={PROJECT_KEY}&ps=500"
    print(f"→ Fetching security hotspots from {url}")

    try:
        res = requests.get(url, auth=(SONAR_TOKEN, ""))
        res.raise_for_status()
        return res.json()
    except Exception as e:
        print("❌ Could not reach SonarQube Hotspots API:", e)
        sys.exit(1)


# -----------------------------
# CALL OLLAMA WITH RETRIES
# -----------------------------
def call_gemma(prompt, retries=3):
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }

    for attempt in range(1, retries + 1):
        try:
            r = requests.post(OLLAMA_API, json=payload, timeout=300)
            r.raise_for_status()
            return r.json().get("response", "")
        except Exception as e:
            print(f"⚠ Ollama error (attempt {attempt}): {e}")
            if "500" in str(e):
                print("💡 Gemma crashed. Retrying in 3 seconds...")
                time.sleep(3)
            else:
                return "⚠ Ollama failed to process this hotspot."

    return "⚠ Ollama repeatedly failed."


# -----------------------------
# ENHANCE SECURITY HOTSPOT
# -----------------------------
def enhance_hotspot(hotspot):
    prompt = f"""
    Analyze this SonarQube SECURITY HOTSPOT and provide in detail:

    - What the hotspot means
    - CWE mapping
    
    Hotspot Rule: {hotspot.get('securityCategory')}
    Message: {hotspot.get('message')}
    Vulnerability Probability: {hotspot.get('vulnerabilityProbability')}
    """
    return call_gemma(prompt)


# -----------------------------
# GENERATE PDF REPORT
# -----------------------------
def generate_pdf_report(hotspots, output_file="enhanced_sonar_hotspots_report.pdf"):
    styles = getSampleStyleSheet()
    story = []

    for hs in hotspots:
        title = f"<b>Hotspot:</b> {hs.get('message')}"
        rule = f"<b>Rule:</b> {hs.get('securityCategory')}"
        prob = f"<b>Probability:</b> {hs.get('vulnerabilityProbability')}"
        enhanced = hs.get("enhanced", "").replace("\n", "<br/>")

        story.append(Paragraph(title, styles["Heading3"]))
        story.append(Paragraph(rule, styles["BodyText"]))
        story.append(Paragraph(prob, styles["BodyText"]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("<b>Analysis:</b>", styles["Heading4"]))
        story.append(Paragraph(enhanced, styles["BodyText"]))
        story.append(Spacer(1, 20))

    pdf = SimpleDocTemplate(output_file, pagesize=A4)
    pdf.build(story)


# -----------------------------
# MAIN
# -----------------------------
def main():
    print("\n🔍 Fetching security hotspots...")
    data_hotspots = fetch_sonar_hotspots()
    hotspots = data_hotspots.get("hotspots", [])

    if not hotspots:
        print("⚠ No security hotspots found.")
        sys.exit(0)

    print(f"🔥 Found {len(hotspots)} security hotspots.")
    enhanced_hotspots = []

    for idx, hotspot in enumerate(hotspots, start=1):
        print(f"\n🔥 ({idx}/{len(hotspots)}) Enhancing Hotspot: {hotspot.get('message')}")
        hotspot["enhanced"] = enhance_hotspot(hotspot)
        enhanced_hotspots.append(hotspot)

    # Save JSON
    with open("enhanced_sonar_hotspots_report.json", "w", encoding="utf-8") as f:
        json.dump(enhanced_hotspots, f, indent=2, ensure_ascii=False)

    print("\n✅ Security Hotspots report saved as enhanced_sonar_hotspots_report.json")

    # Save PDF
    print("📄 Generating PDF report...")
    generate_pdf_report(enhanced_hotspots)
    print("✅ PDF saved as enhanced_sonar_hotspots_report.pdf")


if __name__ == "__main__":
    main()