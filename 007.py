import os
import random
import socket
import time
import hashlib
import string
import subprocess
import shutil

import requests
import whois
import folium
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import webbrowser
from bs4 import BeautifulSoup
from thefuzz import process
from PIL import Image
import base64
from ping3 import ping
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textblob import TextBlob
import pytesseract
import geoip2.database
from twilio.rest import Client

console = Console()

headers = {
    "User-Agent": "Mozilla/5.0"
}
TMDB_API_KEY = os.getenv("TMDB_API_KEY", "06040157f20d0bae45f3bee7bf57566a")
TMDB_BASE_URL = "https://api.themoviedb.org/3"
VT_API_KEY = os.getenv(
    "VT_API_KEY",
    "03caee030cc5a4b3b0dbf536a33c4c849fd3adad06d3f3297df3c2e56ace3fae",
)
IPREGISTRY_API_KEY = os.getenv(
    "IPREGISTRY_API_KEY", "ira_78qZAM7amNE8jXd8l54xiQU1RMvQsB0VyhOO"
)

def tmdb_request(endpoint, params):
    params["api_key"] = TMDB_API_KEY
    url = f"{TMDB_BASE_URL}{endpoint}"
    try:
        r = requests.get(url, params=params, timeout=10)
        if r.status_code == 200:
            return r.json()
        console.print(f"[red]Erreur API TMDb: {r.status_code}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Erreur requête TMDb : {e}[/red]")
        return None


def get_nitro_global_stats():
    """Estimation du nombre d'abonnés Discord Nitro dans le monde"""
    console.print("[bold cyan]\n====== Nitro Global Stats ======[/bold cyan]")

    # Discord a environ 150M d'utilisateurs actifs
    discord_users = 150_000_000  

    # Estimation : 1 à 3% des utilisateurs prennent Nitro
    nitro_basic = int(discord_users * 0.01)
    nitro_premium = int(discord_users * 0.02)

    console.print(f"\n📊 **Estimations des abonnés Nitro :**")
    console.print(f"💎 **Nitro Basic :** ~{nitro_basic:,} abonnés")
    console.print(f"🚀 **Nitro Premium :** ~{nitro_premium:,} abonnés")

    console.input("\nAppuie sur Entrée pour revenir au menu...")

def create_map():
    """ Génère une carte interactive avec des points géolocalisés """
    m = folium.Map(location=[48.8566, 2.3522], zoom_start=6)  # Coordonnées de Paris
    
    # Exemple : Ajout de points d’intérêt
    locations = [
        {"name": "Tour Eiffel", "lat": 48.8584, "lon": 2.2945},
        {"name": "Louvre", "lat": 48.8606, "lon": 2.3376},
        {"name": "Notre-Dame", "lat": 48.8527, "lon": 2.3500},
    ]
    
    for loc in locations:
        folium.Marker([loc["lat"], loc["lon"]], popup=loc["name"], icon=folium.Icon(color="blue")).add_to(m)

    m.save("map.html")  # Enregistre la carte sous forme de fichier HTML

    console.print("[green]✅ Carte créée ! Ouvre 'map.html' pour voir les points géolocalisés.[/green]")

def create_network_graph():
    """ Génère un graphique de réseau montrant les connexions entre individus """
    G = nx.Graph()

    # Exemple : Ajout de connexions entre personnes
    relations = [
        ("Alice", "Bob"),
        ("Bob", "Charlie"),
        ("Alice", "Charlie"),
        ("Charlie", "David"),
        ("David", "Eve"),
    ]

    G.add_edges_from(relations)

    plt.figure(figsize=(8,6))
    nx.draw(G, with_labels=True, node_color="lightblue", edge_color="gray", node_size=2000, font_size=12)
    plt.title("Graphique de réseau")
    plt.show()

    console.print("[green]✅ Graphique généré ![/green]")

def create_dashboard():
    """ Génère un dashboard avec des KPIs """
    data = {
        "Catégorie": ["Mentions", "Influenceurs", "Sources Fiables", "Fuites détectées"],
        "Valeur": [1520, 45, 180, 27]
    }

    df = pd.DataFrame(data)

    plt.figure(figsize=(8,6))
    plt.barh(df["Catégorie"], df["Valeur"], color="blue")
    plt.xlabel("Valeur")
    plt.title("Dashboard - KPIs de l'analyse OSINT")
    plt.show()

    console.print("[green]✅ Dashboard généré avec succès ![/green]")

def global_nitro_stat_server(invite_code):
    """Récupère les membres Nitro sur un serveur Discord via l’invitation"""
    console.print("[bold cyan]\n====== Global Nitro Stat Serveur ======[/bold cyan]")
    
    headers = {"Authorization": "Bot VOTRE_BOT_TOKEN"}
    response = requests.get(f"https://discord.com/api/v10/invites/{invite_code}?with_counts=true", headers=headers)

    if response.status_code == 200:
        data = response.json()
        server_name = data["guild"]["name"]
        boost_count = data["guild"]["premium_subscription_count"]
        member_count = data["approximate_member_count"]

        console.print(f"\n🏰 **Serveur :** {server_name}")
        console.print(f"👥 **Total membres :** {member_count}")
        console.print(f"🚀 **Boosters Nitro (Nitro Premium) :** {boost_count}")
        
        # On peut aussi détecter les membres ayant un rôle "Nitro" si le serveur en a un
        console.print("[yellow]🔍 Vérifie si le serveur attribue un rôle Nitro pour détecter les Nitro Basic ![/yellow]")
    
    else:
        console.print("[red]❌ Erreur : Impossible d'obtenir les infos du serveur.[/red]")

    console.input("\nAppuie sur Entrée pour revenir au menu...")


def search_titles_approximate(query, media_type="movie", limit=10):
    data = tmdb_request(f"/search/{media_type}", {"query": query, "language": "fr-FR", "page": 1})
    if not data or "results" not in data:
        return []
    results = data["results"]
    titles = [r.get("title") or r.get("name") for r in results]
    best_matches = process.extract(query, titles, limit=limit)

    filtered_results = []
    for title, score in best_matches:
        idx = titles.index(title)
        if score >= 60:
            filtered_results.append(results[idx])
    return filtered_results

def get_watch_providers(media_type, tmdb_id, country="FR"):
    data = tmdb_request(f"/{media_type}/{tmdb_id}/watch/providers", {})
    if not data or "results" not in data:
        return []

    country_info = data["results"].get(country)
    if not country_info:
        return []

    providers = country_info.get("flatrate") or country_info.get("rent") or country_info.get("buy")
    if not providers:
        return []

    return [p["provider_name"] for p in providers]

def print_header():
    pass  # Désactive l'affichage du header stylisé

def clear_console():
    """Efface le terminal pour un affichage propre"""
    os.system("cls" if os.name == "nt" else "clear")

def website_vulnerability_scanner():
    print_header()
    console.print("[bold cyan]\n====== Website Vulnerability Scanner ======[/bold cyan]")

    url = console.input("🔗 Entrez l'URL du site à scanner : ").strip()

    try:
        response = requests.get(url)
        console.print(f"\n🔍 Analyse de [bold yellow]{url}[/bold yellow]...\n")
        console.print(f"🔹 Code HTTP : {response.status_code}")

        # Vérifier les headers de sécurité
        security_headers = ["Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"]
        for header in security_headers:
            if header in response.headers:
                console.print(f"[green]✅ {header} présent[/green]")
            else:
                console.print(f"[red]❌ {header} manquant[/red]")

        # Détection des erreurs SQL
        sql_errors = ["mysql_fetch_array()", "You have an error in your SQL syntax", "Error executing SQL", "Undefined index"]
        for error in sql_errors:
            if error in response.text:
                console.print(f"[red]❗ Potentielle vulnérabilité SQL trouvée : {error}[/red]")

        # Analyse des formulaires HTML
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        console.print(f"\n🔎 Nombre de formulaires détectés : {len(forms)}")
        if forms:
            console.print("[yellow]⚠️ Vérifie si les entrées sont bien filtrées contre l’injection SQL.[/yellow]")

        # Vérification des ports ouverts
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080]  # Ports classiques
        console.print("\n🔎 Scan rapide des ports ouverts...")

        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((domain, port))
            if result == 0:
                console.print(f"[red]❌ Port ouvert détecté : {port}[/red]")
            sock.close()

    except requests.exceptions.RequestException as e:
        console.print(f"[red]❌ Erreur lors de l'analyse : {e}[/red]")

    console.input("\nAppuie sur Entrée pour revenir au menu...")


def social_check_tool():
    print_header()
    console.print("[bold cyan]=== Vérification multi-réseaux sociaux ===[/bold cyan]\n")
    username = console.input("🧑‍💻 Entrez le pseudo à vérifier : ").strip()

    # Dictionnaire des sites sociaux classiques avec URL formatées
    sites = {
        # réseaux sociaux classiques
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "Facebook": f"https://www.facebook.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}/",
        "Snapchat": f"https://www.snapchat.com/add/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Dribbble": f"https://dribbble.com/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "DeviantArt": f"https://www.deviantart.com/{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "Behance": f"https://www.behance.net/{username}",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "Goodreads": f"https://www.goodreads.com/{username}",
        "Letterboxd": f"https://letterboxd.com/{username}",
        "Discogs": f"https://www.discogs.com/user/{username}",
        "Patreon": f"https://www.patreon.com/{username}",
        "WhatsApp": f"https://wa.me/{username}",  # souvent numéro, mais on teste
        "Telegram": f"https://t.me/{username}",
        "Stack Overflow": f"https://stackoverflow.com/users/{username}",
        "Quora": f"https://www.quora.com/profile/{username}",
        "AngelList": f"https://angel.co/u/{username}",
        "CodePen": f"https://codepen.io/{username}",
        "Xing": f"https://www.xing.com/profile/{username}",
        "VK": f"https://vk.com/{username}",
        "Ok.ru": f"https://ok.ru/{username}",
        "Myspace": f"https://myspace.com/{username}",
        "SoundClick": f"https://www.soundclick.com/{username}",
    }

    # Deep web - sites onion connus, en mode "statique" (pas vraiment checkable sans TOR)
    deep_web_sites = {
        "Facebook (Onion)": "https://www.facebookcorewwwi.onion/",
        "DuckDuckGo (Onion)": "https://3g2upl4pq6kufc4m.onion/",
        "ProtonMail (Onion)": "https://protonirockerxow.onion/",
        "Riseup (Onion)": "https://5jp7xtm5tb4xqoz3.onion/",
        "Tor Metrics (Onion)": "http://rougmnvswfsmd4dq.onion/",
    }

    console.print(f"\n🔎 Recherche du pseudo [bold yellow]{username}[/bold yellow] sur plusieurs plateformes classiques...\n")

    for site, url in sites.items():
        try:
            r = requests.head(url, headers=headers, allow_redirects=True, timeout=5)
            if r.status_code == 200:
                console.print(f"[green]✔ {site} trouvé :[/green] [blue underline]{url}[/blue underline]")
            else:
                console.print(f"[red]✘ {site} non trouvé[/red]")
        except Exception as e:
            console.print(f"[red]⚠ {site} erreur : {e}[/red]")

    console.print("\n[bold cyan]=== Deep Web (sites .onion connus) ===[/bold cyan]")
    for site, url in deep_web_sites.items():
        console.print(f"🔗 {site} : [magenta]{url}[/magenta]")

    console.print("\n[bold magenta]Recherche terminée.[/bold magenta]\n")
    console.input("Appuyez sur Entrée pour revenir au menu...")

def generate_random_ip():
    """Génère une adresse IPv4 aléatoire"""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"


def get_valid_ip():
    """Récupère une vraie adresse IP publique"""
    try:
        response = requests.get("https://api.ipify.org?format=json")
        if response.status_code == 200:
            return response.json()["ip"]
        else:
            return None
    except Exception:
        return None

def generate_valid_ip():
    """Génère une adresse IP publique réaliste"""
    # Sélection d'un bloc d'IP utilisé par les ISP (non-réservé)
    first_octet = random.choice([1, 2, 3, 5, 23, 45, 57, 78, 89, 100, 123, 150, 176, 198, 203, 210, 220])
    return f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"



def ip_generator():
    print_header()
    console.print("[bold cyan]\n====== IP GENERATOR ======[/bold cyan]")

    # Entrée du webhook Discord
    webhook_url = console.input("\n🔗 Entrez votre webhook Discord : ").strip()

    # Nombre d'IP à générer
    num_ips = console.input("💻 Combien d'IP veux-tu générer ? ")

    try:
        num_ips = int(num_ips)
        if num_ips <= 0:
            console.print("[red]❌ Nombre invalide ![/red]")
            return
    except ValueError:
        console.print("[red]❌ Tu dois entrer un nombre valide ![/red]")
        return

    generated_ips = []

    for _ in range(num_ips):
        ip = generate_valid_ip()  # Génération correcte d'IP aléatoire IPv4
        generated_ips.append(ip)
        console.print(f"✅ IP générée : [bold yellow]{ip}[/bold yellow]")

    # Envoi des IP sur Discord via le webhook
    data = {"content": "**IP GENERATOR - Résultats :**\n" + "\n".join(generated_ips)}
    requests.post(webhook_url, json=data)

    console.print("\n🚀 Toutes les IP aléatoires ont été envoyées sur Discord !")
    console.input("🔄 Appuie sur Entrée pour revenir au menu...")

def osint_film_serie():
    console.clear()
    title = Text("007 OSINT", style="bold red", justify="center")
    subtitle = Text("Created by KRATORAK", style="italic green", justify="center")
    panel = Panel(Align.center(Text.assemble(title, "\n", subtitle)), style="bold blue", box=box.DOUBLE)
    console.print(panel)

    query = console.input("\n🎥 Entrez le nom du film ou série : ").strip()
    console.print("\n🔍 Recherche approximative...")

    movies = search_titles_approximate(query, "movie", limit=5)
    series = search_titles_approximate(query, "tv", limit=5)

    console.print(f"\n[bold yellow]{len(movies)} films trouvés[/bold yellow]")
    console.print(f"[bold yellow]{len(series)} séries trouvées[/bold yellow]\n")

    def print_info(results, media_type):
        for i, res in enumerate(results, 1):
            title = res.get("title") or res.get("name")
            release_date = res.get("release_date") or res.get("first_air_date") or "N/A"
            tmdb_id = res.get("id")
            providers = get_watch_providers(media_type, tmdb_id)
            providers_str = ", ".join(providers) if providers else "Non disponible"
            console.print(f"[cyan]{i}. {title}[/cyan] ({release_date})")
            console.print(f"    Plateformes disponibles: [green]{providers_str}[/green]\n")

    if movies:
        console.print("[bold underline]Films :[/bold underline]")
        print_info(movies, "movie")

    if series:
        console.print("[bold underline]Séries :[/bold underline]")
        print_info(series, "tv")

    if not movies and not series:
        console.print("[red]Aucun résultat trouvé pour votre recherche.[/red]")

    console.input("\nAppuyez sur Entrée pour revenir au menu...")



def get_domain_info():
    domain = console.input("🌐 Entrez un nom de domaine : ").strip()
    console.print(f"\n🌐 Analyse du domaine : [bold yellow]{domain}[/bold yellow]\n")

    try:
        ip = socket.gethostbyname(domain)
        console.print(f"🖥️ Adresse IP : {ip}")
    except socket.gaierror:
        console.print("[red]Impossible de résoudre l'IP.[/red]")

    try:
        w = whois.whois(domain)
        console.print(f"📅 Expiration du domaine : {w.expiration_date}")
        console.print(f"👤 Propriétaire : {w.name} ({w.org})")
        console.print(f"📩 Email WHOIS : {w.emails}")
    except Exception as e:
        console.print(f"[red]Erreur WHOIS : {e}[/red]")

    console.input("\nAppuie sur Entrée pour revenir au menu...")

def check_url_vt():
    url = console.input("🔗 Entrez une URL à analyser : ").strip()
    console.print(f"\n🔍 Analyse de l'URL : [bold yellow]{url}[/bold yellow]\n")
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)

    if r.status_code == 200:
        json_data = r.json()
        score = json_data["data"]["attributes"]["last_analysis_stats"]
        console.print(f"🦠 Détections : {score}")
    else:
        console.print("[red]Erreur VirusTotal[/red]")

    console.input("\nAppuie sur Entrée pour revenir au menu...")


def discord_token_info():
    print_header()
    console.print("[bold cyan]\n====== Discord Token Info ======[/bold cyan]")
    token = console.input("🔑 Entrez le token Discord : ").strip()

    headers = {"Authorization": token}
    r = requests.get("https://discord.com/api/v10/users/@me", headers=headers)

    if r.status_code == 200:
        user_data = r.json()
        console.print(f"\n👤 Nom : {user_data['username']}#{user_data['discriminator']}")
        console.print(f"🆔 ID Discord : {user_data['id']}")
    else:
        console.print("[red]❌ Token invalide ou erreur.[/red]")

    console.input("\nAppuie sur Entrée pour revenir au menu...")

def discord_webhook_info():
    print_header()
    console.print("[bold cyan]\n====== Discord Webhook Info ======[/bold cyan]")
    webhook_url = console.input("🔗 Entrez l'URL du webhook Discord : ").strip()

    r = requests.get(webhook_url)

    if r.status_code == 200:
        webhook_data = r.json()
        console.print(f"\n🔧 Nom du webhook : {webhook_data['name']}")
        console.print(f"📍 Serveur ID : {webhook_data['guild_id']}")
        console.print(f"💬 Channel ID : {webhook_data['channel_id']}")
    else:
        console.print("[red]❌ Webhook invalide ou erreur.[/red]")

    console.input("\nAppuie sur Entrée pour revenir au menu...")

def discord_webhook_generator():
    print_header()
    console.print("[bold cyan]\n====== Discord Webhook Generator ======[/bold cyan]")
    webhook_url = console.input("🔗 Entrez le webhook Discord : ").strip()
    message = console.input("💬 Entrez le message à envoyer : ").strip()

    data = {"content": message}
    r = requests.post(webhook_url, json=data)

    if r.status_code == 204:
        console.print("[green]✅ Message envoyé avec succès ![/green]")
    else:
        console.print("[red]❌ Erreur lors de l’envoi du message.[/red]")

    console.input("\nAppuie sur Entrée pour revenir au menu...")

def discord_server_info():
    """ Récupère les infos d'un serveur Discord via son lien d'invitation """

    print_header()
    console.print("[bold cyan]\n====== Discord Server Info ======[/bold cyan]")

    invite_code = console.input("🔗 Entrez l'invitation du serveur Discord : ").strip()
    invite_code = invite_code.split("/")[-1]  # Récupère juste le code d'invitation

    headers = {"Authorization": "Bot VOTRE_BOT_TOKEN"}
    response = requests.get(f"https://discord.com/api/v10/invites/{invite_code}?with_counts=true", headers=headers)

    if response.status_code == 200:
        data = response.json()
        server_name = data["guild"]["name"]
        member_count = data["approximate_member_count"]
        online_count = data["approximate_presence_count"]

        console.print(f"\n🏰 **Serveur :** {server_name}")
        console.print(f"👥 **Membres :** {member_count}")
        console.print(f"🟢 **Membres en ligne :** {online_count}")

    elif response.status_code == 401:
        console.print("[red]❌ Erreur : Token d’authentification invalide ou manquant.[/red]")
    elif response.status_code == 404:
        console.print("[red]❌ Erreur : Invitation invalide ou serveur introuvable.[/red]")
    else:
        console.print(f"[red]❌ Erreur inconnue ({response.status_code}).[/red]")

    console.input("\nAppuie sur Entrée pour revenir au menu...")

def scan_ports(ip):
    console.print(f"🔍 Scan Nmap en cours pour {ip}...", style="bold yellow")
    try:
        result = subprocess.check_output(
            ["nmap", "-Pn", "-F", ip],
            stderr=subprocess.STDOUT,
            text=True
        )
        console.print("\n🛡️ Résultat du scan Nmap :", style="bold cyan")
        console.print(result)
    except subprocess.CalledProcessError as e:
        console.print(f"❌ Erreur lors du scan Nmap :\n{e.output}", style="bold red", justify="center")

def get_ip_location():
    console.print("[cyan]📍 Géolocalisation IP via ipregistry.co après scan Nmap[/cyan]")
    ip = console.input("🔎 Entrez l'adresse IP à analyser : ").strip()

    if not ip:
        console.print("❌ IP invalide, réessaie.", style="bold red", justify="center")
        return

    scan_ports(ip)  # 🔥 Étape 1 : Scan de ports

    url = f"https://api.ipregistry.co/{ip}?key={IPREGISTRY_API_KEY}"

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()

        loc = data["location"]
        sec = data["security"]
        company = data.get("company", {})
        address = f"{loc['city']}, {loc['region']['name']}, {loc['postal']}, {loc['country']['name']}"

        infos = {
            "Ville": loc["city"],
            "Code Postal": loc["postal"],
            "Latitude": loc["latitude"],
            "Longitude": loc["longitude"],
            "Adresse (approximative)": address,
            "Organisation": company.get("name", "N/A"),
            "VPN / Proxy / TOR": "Oui" if sec["is_vpn"] or sec["is_proxy"] or sec["is_tor"] else "Non"
        }

        console.print("\n🌍 Informations géographiques :", style="bold cyan")
        for key, val in infos.items():
            console.print(f"🔹 {key:20}: {val}")

        # 🗺️ Carte interactive
        m = folium.Map(location=[loc["latitude"], loc["longitude"]], zoom_start=13)
        folium.Marker([loc["latitude"], loc["longitude"]], popup=address, tooltip="📍 Cible estimée").add_to(m)
        m.save("geo_ip_map.html")
        webbrowser.open("geo_ip_map.html")
        console.print("\n🗺️ Carte ouverte dans le navigateur", style="bold green")

    except Exception as e:
        console.print(f"❌ Erreur : {e}", style="bold red", justify="center")

    console.input("\nAppuie sur Entrée pour revenir au menu...")

def sentiment_analysis():
    """ Analyse du sentiment d’un texte (positif, neutre, négatif) """
    console.print("[cyan]💬 Analyse de Sentiment d’un texte[/cyan]")
    text = console.input("📝 Entrez le texte à analyser : ")

    analysis = TextBlob(text)
    sentiment = analysis.sentiment.polarity

    if sentiment > 0:
        console.print("[green]✅ Sentiment positif.[/green]")
    elif sentiment < 0:
        console.print("[red]❌ Sentiment négatif.[/red]")
    else:
        console.print("[yellow]🔶 Sentiment neutre.[/yellow]")



def identity_detection():
    """ Vérifie si un pseudo est utilisé sur plusieurs sites """
    console.print("[cyan]🎭 Détection d’identités multiples[/cyan]")
    username = console.input("🔍 Entrez un pseudo : ").strip()

    platforms = [
        f"https://twitter.com/{username}",
        f"https://github.com/{username}",
        f"https://www.instagram.com/{username}/",
        f"https://www.tiktok.com/@{username}",
        f"https://www.reddit.com/user/{username}",
    ]

    for site in platforms:
        response = requests.get(site)
        if response.status_code == 200:
            console.print(f"[green]✅ {username} existe sur {site}[/green]")
        else:
            console.print(f"[red]❌ {username} n’a pas été trouvé sur {site}[/red]")

def time_analysis():
    """ Analyse temporelle des tendances et événements """
    console.print("[cyan]⏳ Time Analysis - Visualisation de l’évolution des tendances[/cyan]")

    # Exemple de données temporelles
    data = {
        "Date": ["2024-01-01", "2024-02-01", "2024-03-01", "2024-04-01"],
        "Mentions": [120, 150, 180, 240]
    }

    df = pd.DataFrame(data)
    df["Date"] = pd.to_datetime(df["Date"])

    plt.figure(figsize=(8,6))
    plt.plot(df["Date"], df["Mentions"], marker='o', linestyle='-', color='blue')
    plt.xlabel("Date")
    plt.ylabel("Nombre de mentions")
    plt.title("Évolution des tendances au fil du temps")
    plt.grid()
    plt.show()


def social_network_analysis():
    """ Analyse des connexions et influenceurs sur un réseau social """
    console.print("[cyan]📊 Analyse avancée des réseaux sociaux[/cyan]")
    
    # Exemple de structure de réseau social
    G = nx.Graph()
    G.add_edges_from([
        ("Alice", "Bob"),
        ("Bob", "Charlie"),
        ("Charlie", "David"),
        ("David", "Eve"),
        ("Eve", "Alice"),
        ("Alice", "Charlie")
    ])

    plt.figure(figsize=(6,6))
    nx.draw(G, with_labels=True, node_color="skyblue", edge_color="gray", font_weight="bold")
    plt.title("Graphique des connexions sociales")
    plt.show()

    console.input("\nAppuie sur Entrée pour revenir au menu...")


def article_search():
    """ Recherche automatique d’articles et sources d’information fiables """
    console.print("[cyan]🌎 Recherche automatique d’articles sur un sujet[/cyan]")
    query = console.input("🔎 Entrez un sujet : ").strip()

    # Recherche sur Wikipedia
    wiki_url = f"https://fr.wikipedia.org/wiki/{query.replace(' ', '_')}"
    try:
        response = requests.get(wiki_url)
        soup = BeautifulSoup(response.text, "html.parser")
        intro = soup.find("p").text
        console.print(f"📖 Wikipedia : {intro[:300]}...\n🔗 {wiki_url}")
    except:
        console.print("❌ Impossible d’extraire Wikipedia.")

    # Recherche sur Google News
    news_url = f"https://www.google.com/search?q={query.replace(' ', '+')}&tbm=nws"
    console.print(f"📰 Articles sur Google News : {news_url}")

    # ✅ Ajout correct de la pause pour éviter le clear immédiat
    console.input("\nAppuie sur Entrée pour revenir au menu...")



def ocr_text_extraction():
    """ Extraction de texte depuis une image """
    console.print("[cyan]🖼️ OCR - Extraction de texte sur image[/cyan]")
    image_path = console.input("📷 Entrez le chemin de l’image : ").strip()

    text = pytesseract.image_to_string(Image.open(image_path))
    console.print(f"📝 Texte extrait :\n{text}")


def osint_alert_system():
    """ Surveillance d’un sujet et alertes en temps réel (avec option de sortie) """
    console.print("[cyan]🚨 OSINT Alert System - Suivi d’un sujet[/cyan]")
    query = console.input("🔎 Entrez un sujet à surveiller (ou 'q' pour quitter) : ").strip()

    if query.lower() == "q":
        console.print("[red]❌ Surveillance annulée.[/red]")
        return

    news_url = f"https://www.google.com/search?q={query.replace(' ', '+')}&tbm=nws"

    while True:
        console.print(f"🔍 Vérification des nouvelles infos sur {query}...")
        response = requests.get(news_url)
        soup = BeautifulSoup(response.text, "html.parser")

        first_news = soup.find("h3")
        if first_news:
            console.print(f"⚠️ Nouvelle info : {first_news.text}")
        else:
            console.print("❌ Aucune info trouvée pour le moment.")

        console.print("\n🛑 Tape 'q' et appuie sur Entrée pour quitter la surveillance...")
        stop = console.input().strip()
        if stop.lower() == "q":
            console.print("[red]❌ Surveillance arrêtée.[/red]")
            break

        time.sleep(600)  # Vérifie toutes les 10 minutes




def show_good_links():
    print_header()
    console.print("[bold cyan]\n====== Les Bons Liens ======[/bold cyan]\n")

    links = {
        "Anime-Sama": "https://anime-sama.fr/",
        "Xalaflix": "https://xalaflix.io/",
        "Limpaz": "https://www.limpaz.fr/"
    }

    for name, url in links.items():
        console.print(f"🔗 {name} : [blue underline]{url}[/blue underline]")

    console.input("\nAppuie sur Entrée pour revenir au menu...")


def reverse_ip_lookup():
    ip = console.input("Adresse IP : ").strip()
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        console.print(f"[green]Domaine associé : {host}[/green]")
    except Exception:
        console.print("[red]Aucun domaine trouvé pour cette IP[/red]")
    console.input("Entrée pour revenir...")


def ping_host():
    host = console.input("Hôte à ping : ").strip()
    try:
        result = ping(host, unit="ms")
        if result is None:
            console.print("[red]Aucune réponse[/red]")
        else:
            console.print(f"[green]{host} a répondu en {result:.2f} ms[/green]")
    except Exception as e:
        console.print(f"[red]Erreur de ping : {e}[/red]")
    console.input("Entrée pour revenir...")


def http_headers_viewer():
    url = console.input("URL : ").strip()
    try:
        r = requests.get(url, headers=headers, timeout=10)
        for k, v in r.headers.items():
            console.print(f"[cyan]{k}[/cyan]: {v}")
    except Exception as e:
        console.print(f"[red]Erreur : {e}[/red]")
    console.input("Entrée pour revenir...")


def random_password_generator():
    length_str = console.input("Longueur du mot de passe : ").strip()
    if not length_str.isdigit():
        console.print("[red]Longueur invalide[/red]")
        return
    length = int(length_str)
    chars = string.ascii_letters + string.digits + string.punctuation
    pwd = "".join(random.choice(chars) for _ in range(length))
    console.print(f"[green]{pwd}[/green]")
    console.input("Entrée pour revenir...")


def base64_encoder():
    text = console.input("Texte à encoder : ")
    encoded = base64.b64encode(text.encode()).decode()
    console.print(f"[green]{encoded}[/green]")
    console.input("Entrée pour revenir...")


def base64_decoder():
    text = console.input("Texte base64 : ")
    try:
        decoded = base64.b64decode(text).decode()
        console.print(f"[green]{decoded}[/green]")
    except Exception:
        console.print("[red]Décodage impossible[/red]")
    console.input("Entrée pour revenir...")


def hash_generator():
    text = console.input("Texte à hasher : ")
    algo = console.input("Algorithme (md5, sha1, sha256) : ").strip().lower()
    func = getattr(hashlib, algo, None)
    if not func:
        console.print("[red]Algorithme inconnu[/red]")
    else:
        console.print(f"[green]{func(text.encode()).hexdigest()}[/green]")
    console.input("Entrée pour revenir...")


def image_metadata_viewer():
    path = console.input("Chemin de l'image : ").strip()
    try:
        img = Image.open(path)
        info = img._getexif() or {}
        if not info:
            console.print("[yellow]Aucune métadonnée trouvée[/yellow]")
        else:
            for k, v in info.items():
                console.print(f"[cyan]{k}[/cyan]: {v}")
    except Exception as e:
        console.print(f"[red]Erreur : {e}[/red]")
    console.input("Entrée pour revenir...")


def detect_language():
    text = console.input("Texte : ")
    try:
        lang = TextBlob(text).detect_language()
        console.print(f"[green]Langue détectée : {lang}[/green]")
    except Exception as e:
        console.print(f"[red]Erreur : {e}[/red]")
    console.input("Entrée pour revenir...")


def open_website():
    url = console.input("URL à ouvrir : ").strip()
    webbrowser.open(url)
    console.print(f"[green]Ouverture de {url}[/green]")
    console.input("Entrée pour revenir...")

def get_terminal_size():
    return shutil.get_terminal_size((80, 20))

def center_text_vertically(content: str) -> str:
    """
    Centre verticalement un texte dans le terminal.
    """
    lines = content.strip('\n').split('\n')
    term_height = get_terminal_size().lines
    padding = max(0, (term_height - len(lines)) // 2)
    return "\n" * padding + "\n".join(lines)

def spiderman_intro():
    spider_art = r"""
[bold]
                      /^--^\     /^--^\     /^--^\
                      \____/     \____/     \____/
                     /      \   /      \   /      \
KAT                 |        | |        | |        |
                     \__  __/   \__  __/   \__  __/
|^|^|^|^|^|^|^|^|^|^|^|\ \^|^|^|^/ /^|^|^|^|\ \^|^|^|^|^|^|^|^|^|^|^|
| | | | | | | | | | | | |\ \| | |/ /| | | | | | \ \ | | | | | | | | | | |
########################/ /######\ \###########/ /#######################
| | | | | | | | | | | | \/| | | | \/| | | | | |\/ | | | | | | | | | | | |
|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|

[/bold]
"""

    for i in range(10):
        color = "green" if i % 2 == 0 else "red"
        console.clear()
        centered_spider = center_text_vertically(spider_art)
        console.print(centered_spider, style=f"bold {color}")
        time.sleep(0.5)
    console.clear()

def show_startup_banner():
    banner = r"""
                             ▒█████    ██████  ██▓ ███▄    █ ▄▄▄█████▓    ███▄    █ ▓█████ ▄▄▄█████▓               
                           ▒██▒  ██▒▒██    ▒ ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒    ██ ▀█   █ ▓█   ▀ ▓  ██▒ ▓▒               
                           ▒██░  ██▒░ ▓██▄   ▒██▒▓██  ▀█ ██▒▒ ▓██░ ▒░   ▓██  ▀█ ██▒▒███   ▒ ▓██░ ▒░               
                           ▒██   ██░  ▒   ██▒░██░▓██▒  ▐▌██▒░ ▓██▓ ░    ▓██▒  ▐▌██▒▒▓█  ▄ ░ ▓██▓ ░                
                           ░ ████▓▒░▒██████▒▒░██░▒██░   ▓██░  ▒██▒ ░    ▒██░   ▓██░░▒████▒  ▒██▒ ░                
                           ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▓  ░ ▒░   ▒ ▒   ▒ ░░      ░ ▒░   ▒ ▒ ░░ ▒░ ░  ▒ ░░                  
                             ░ ▒ ▒░ ░ ░▒  ░ ░ ▒ ░░ ░░   ░ ▒░    ░       ░ ░░   ░ ▒░ ░ ░  ░    ░                   
                           ░ ░ ░ ▒  ░  ░  ░   ▒ ░   ░   ░ ░   ░            ░   ░ ░    ░     ░                     
                               ░ ░        ░   ░           ░                      ░    ░  ░          ░                       
    """
    console.clear()
    centered_banner = center_text_vertically(banner)
    console.print(f"[bold green]{centered_banner}[/bold green]")
    console.print("\n[bold green]Appuie sur Entrée pour lancer le MultiTool...[/bold green]", justify="center")
    console.input()

def update_print():
    console.clear()
    print_header()
    banner = r"""
                              ▒█████    ██████  ██▓ ███▄    █ ▄▄▄█████▓    ███▄    █ ▓█████ ▄▄▄█████▓
                            ▒██▒  ██▒▒██    ▒ ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒    ██ ▀█   █ ▓█   ▀ ▓  ██▒ ▓▒
                            ▒██░  ██▒░ ▓██▄   ▒██▒▓██  ▀█ ██▒▒ ▓██░ ▒░   ▓██  ▀█ ██▒▒███   ▒ ▓██░ ▒░
                            ▒██   ██░  ▒   ██▒░██░▓██▒  ▐▌██▒░ ▓██▓ ░    ▓██▒  ▐▌██▒▒▓█  ▄ ░ ▓██▓ ░
                            ░ ████▓▒░▒██████▒▒░██░▒██░   ▓██░  ▒██▒ ░    ▒██░   ▓██░░▒████▒  ▒██▒ ░
                            ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▓  ░ ▒░   ▒ ▒   ▒ ░░      ░ ▒░   ▒ ▒ ░░ ▒░ ░  ▒ ░░
                              ░ ▒ ▒░ ░ ░▒  ░ ░ ▒ ░░ ░░   ░ ▒░    ░       ░ ░░   ░ ▒░ ░ ░  ░    ░
                            ░ ░ ░ ▒  ░  ░  ░   ▒ ░   ░   ░ ░   ░            ░   ░ ░    ░     ░
                              ░ ░        ░   ░           ░                      ░    ░  ░          ░
    """
    for line in banner.strip("\n").split("\n"):
        console.print(line, style="bold green", justify="center")

def main_menu_page1():
    while True:
        update_print()
        console.print("╔══════════════════════════════════════════════════════════════════════════════════╗", style="bold red", justify="center")
        console.print("║ OS1nT nEtW0rk MultiTool | v1.0.0 | [0] > Support (discord)    [ - ] [ □ ] [ X ]  ║", style="bold red", justify="center")
        console.print("║══════════════════════════════════════════════════════════════════════════════════║", style="bold red", justify="center")

        # Options 01 à 20
        console.print("║ [01] > Website Vulnerability Scanner     [11] > Détection identités multiples    ║", style="bold red", justify="center")
        console.print("║ [02] > WHOIS & DNS Lookup                 [12] > Vérif multi réseaux sociaux     ║", style="bold red", justify="center")
        console.print("║ [03] > URL Scanner (VirusTotal)           [13] > Dashboards avec KPIs            ║", style="bold red", justify="center")
        console.print("║ [04] > IP Scanner                         [14] > Cartes interactives             ║", style="bold red", justify="center")
        console.print("║ [05] > IP Port Scanner                    [15] > Graphiques de réseau            ║", style="bold red", justify="center")
        console.print("║ [06] > IP Geolocalisation                  [16] > Analyse réseaux sociaux        ║", style="bold red", justify="center")
        console.print("║ [07] > IP Generator                        [17] > Sentiment Analysis             ║", style="bold red", justify="center")
        console.print("║ [08] > Data Scraping OSINT                 [18] > Time Analysis                  ║", style="bold red", justify="center")
        console.print("║ [09] > Recherche d'articles                [19] > Nitro Stats                    ║", style="bold red", justify="center")
        console.print("║ [10] > OSINT Film & Série                  [20] > Nitro Global Stats             ║", style="bold red", justify="center")

        # Option navigation "next page"
        console.print("║                                                              [n] > Page suivante   ║", style="bold red", justify="center")
        console.print("╚══════════════════════════════════════════════════════════════════════════════════╝", style="bold red", justify="center")

        choix = console.input("\n[bold green]appuie sur [N] pour la page suivante est [P] pour la page précédente : [/bold green]").strip().lower()

        if choix == 'n':
            main_menu_page2()
            clear_console()
            print_header()
            continue

        choix = choix.zfill(2)

        # Gestion des choix page 1
        if choix == "01":
            website_vulnerability_scanner()
        elif choix == "02":
            get_domain_info()
        elif choix == "03":
            check_url_vt()
        elif choix == "04":
            get_ip_location()
        elif choix == "05":
            scan_ports(console.input("IP à scanner : ").strip())
        elif choix == "06":
            get_ip_location()
        elif choix == "07":
            ip_generator()
        elif choix == "08":
            data_scraping_osint()
        elif choix == "09":
            article_search()
        elif choix == "10":
            osint_film_serie()
        elif choix == "11":
            identity_detection()
        elif choix == "12":
            social_check_tool()
        elif choix == "13":
            create_dashboard()
        elif choix == "14":
            create_map()
        elif choix == "15":
            create_network_graph()
        elif choix == "16":
            social_network_analysis()
        elif choix == "17":
            sentiment_analysis()
        elif choix == "18":
            time_analysis()
        elif choix == "19":
            invite_code = console.input("Code d'invitation Discord : ").strip()
            get_nitro_boosters(invite_code)
        elif choix == "20":
            get_nitro_global_stats()
        elif choix == "29":
            console.print("\n[bold green]👋 A bientôt, merci d'avoir utilisé le MultiTool OSINT ![/bold green]")
            break
        else:
            console.print("[bold red]❌ Choix invalide, réessaie.[/bold red]")

        console.input("[bold yellow]👉 Appuie sur Entrée pour continuer...[/bold yellow]")

def main_menu_page2():
    while True:
        update_print()  # Affiche clear + ASCII art + header centré
        
        # Préparer les lignes du menu dans une liste
        menu_lines = [
            "╔══════════════════════════════════════════════════════════════════════════════════╗",
            "║ OS1nT nEtW0rk MultiTool | v1.0.0 | [0] > Support (discord)    [ - ] [ □ ] [ X ]  ║",
            "║══════════════════════════════════════════════════════════════════════════════════║",
            "║ [21] > Global Nitro Stat Server           [25] > Discord Server Info             ║",
            "║ [22] > Discord Token Info                  [26] > OCR Text Extraction            ║",
            "║ [23] > Discord Webhook Info                [27] > Show Good Links                ║",
            "║ [24] > Discord Webhook Generator           [28] > OSINT Alert System             ║",
            "║ [30] > Discord Token Tools                [29] > Quitter                         ║",
            "║ [p] > Page précédente                                      [n] > Page suivante   ║",
            "╚══════════════════════════════════════════════════════════════════════════════════╝",
        ]
        
        # Afficher chaque ligne centrée horizontalement dans la console
        for line in menu_lines:
            console.print(line, style="bold red", justify="center")

        choix = console.input("\n[bold green]👉 Numéro de l'option ou 'p' pour la page précédente : [/bold green]").strip().lower()


        if choix == 'p':
            return  # Retour à la page 1
        if choix == 'n':
            main_menu_page3()
            continue

        choix = choix.zfill(2)

        # Gestion des choix page 2
        if choix == "21":
            global_nitro_stat_server(console.input("Invitation Discord : ").strip())
        elif choix == "22":
            discord_token_info()
        elif choix == "23":
            discord_webhook_info()
        elif choix == "24":
            discord_webhook_generator()
        elif choix == "25":
            discord_server_info()
        elif choix == "26":
            ocr_text_extraction()
        elif choix == "27":
            show_good_links()
        elif choix == "28":
            osint_alert_system()
        elif choix == "30":
            token_tools_menu()
        elif choix == "29":
            console.print("\n[bold green]👋 A bientôt, merci d'avoir utilisé le MultiTool OSINT ![/bold green]")
            exit()
        else:
            console.print("[bold red]❌ Choix invalide, réessaie.[/bold red]")

        console.input("[bold yellow]👉 Appuie sur Entrée pour continuer...[/bold yellow]")


def main_menu_page3():
    while True:
        update_print()
        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════════╗",
            "║ OS1nT nEtW0rk MultiTool | v1.0.0 | [0] > Support (discord)    [ - ] [ □ ] [ X ]  ║",
            "║══════════════════════════════════════════════════════════════════════════════════║",
            "║ [31] > Reverse IP Lookup                 [36] > Base64 Decoder                   ║",
            "║ [32] > Ping Host                         [37] > Hash Generator                   ║",
            "║ [33] > HTTP Headers Viewer               [38] > Image Metadata Viewer            ║",
            "║ [34] > Random Password Generator         [39] > Language Detector                ║",
            "║ [35] > Base64 Encoder                    [40] > Open URL in Browser              ║",
            "║ [41] > Envoyer SMS Twilio                                                        ║",  # Ajout de l'option
            "║ [p] > Page précédente                                                            ║",
            "╚══════════════════════════════════════════════════════════════════════════════════╝",
        ]
        for line in lines:
            console.print(line, style="bold blue", justify="center")

        choix = console.input("\n[bold green]👉 Numéro de l'option ou 'p' pour la page précédente : [/bold green]").strip().lower()
        if choix == 'p':
            return
        choix = choix.zfill(2)
        if choix == "31":
            reverse_ip_lookup()
        elif choix == "32":
            ping_host()
        elif choix == "33":
            http_headers_viewer()
        elif choix == "34":
            random_password_generator()
        elif choix == "35":
            base64_encoder()
        elif choix == "36":
            base64_decoder()
        elif choix == "37":
            hash_generator()
        elif choix == "38":
            image_metadata_viewer()
        elif choix == "39":
            detect_language()
        elif choix == "40":
            open_website()
        elif choix == "41":
            send_sms_twilio()
        else:
            console.print("[bold red]❌ Choix invalide, réessaie.[/bold red]")
        console.input("[bold yellow]👉 Appuie sur Entrée pour continuer...[/bold yellow]")
def discord_api_request(token, method, endpoint, payload=None):
    """Helper for Discord API requests"""
    url = f"https://discord.com/api/v9/{endpoint}"
    headers = {"Authorization": token}
    try:
        r = requests.request(method, url, json=payload, headers=headers, timeout=10)
        if r.status_code in (200, 201, 204):
            console.print("[green]✔ Opération réussie[/green]")
        else:
            console.print(f"[red]Erreur {r.status_code}: {r.text}[/red]")
        return r
    except Exception as e:
        console.print(f"[red]Erreur requête Discord: {e}[/red]")
        return None


def token_login():
    token = console.input("Token Discord : ").strip()
    r = discord_api_request(token, "GET", "users/@me")
    if r and r.status_code == 200:
        data = r.json()
        console.print(f"Connecté en tant que {data.get('username')}#{data.get('discriminator')}")
    console.input("Entrée pour revenir...")


def token_change_language():
    token = console.input("Token Discord : ").strip()
    locale = console.input("Langue (ex: fr, en-US) : ").strip()
    discord_api_request(token, "PATCH", "users/@me/settings", {"locale": locale})
    console.input("Entrée pour revenir...")


def token_change_description():
    token = console.input("Token Discord : ").strip()
    bio = console.input("Nouvelle description : ").strip()
    discord_api_request(token, "PATCH", "users/@me", {"bio": bio})
    console.input("Entrée pour revenir...")


def token_change_username():
    token = console.input("Token Discord : ").strip()
    username = console.input("Nouveau pseudo : ").strip()
    password = console.input("Mot de passe : ").strip()
    discord_api_request(token, "PATCH", "users/@me", {"username": username, "password": password})
    console.input("Entrée pour revenir...")


def token_change_status():
    token = console.input("Token Discord : ").strip()
    status = console.input("Nouveau statut : ").strip()
    payload = {"custom_status": {"text": status}}
    discord_api_request(token, "PATCH", "users/@me/settings", payload)
    console.input("Entrée pour revenir...")


def token_change_avatar():
    token = console.input("Token Discord : ").strip()
    path = console.input("Chemin de l'image : ").strip()
    try:
        with open(path, "rb") as f:
            encoded = base64.b64encode(f.read()).decode("utf-8")
        payload = {"avatar": f"data:image/png;base64,{encoded}"}
        discord_api_request(token, "PATCH", "users/@me", payload)
    except FileNotFoundError:
        console.print("[red]Fichier introuvable[/red]")
    console.input("Entrée pour revenir...")


def token_reset_avatar():
    token = console.input("Token Discord : ").strip()
    discord_api_request(token, "PATCH", "users/@me", {"avatar": None})
    console.input("Entrée pour revenir...")


def token_change_email():
    token = console.input("Token Discord : ").strip()
    email = console.input("Nouvel email : ").strip()
    password = console.input("Mot de passe : ").strip()
    discord_api_request(token, "PATCH", "users/@me", {"email": email, "password": password})
    console.input("Entrée pour revenir...")


def token_change_password():
    token = console.input("Token Discord : ").strip()
    old_password = console.input("Ancien mot de passe : ").strip()
    new_password = console.input("Nouveau mot de passe : ").strip()
    payload = {"password": new_password, "old_password": old_password}
    discord_api_request(token, "PATCH", "users/@me", payload)
    console.input("Entrée pour revenir...")


def token_logout():
    token = console.input("Token Discord : ").strip()
    discord_api_request(token, "POST", "auth/logout", {"token": token})
    console.input("Entrée pour revenir...")


def token_tools_menu():
    while True:
        update_print()
        lines = [
            "╔════════════════════════ Token Tools ═══════════════════════╗",
            "║ [01] > Login via token                                     ║",
            "║ [02] > Changer la langue                                   ║",
            "║ [03] > Changer la description                              ║",
            "║ [04] > Changer le pseudo                                   ║",
            "║ [05] > Changer le statut                                   ║",
            "║ [06] > Changer l'avatar                                    ║",
            "║ [07] > Réinitialiser l'avatar                              ║",
            "║ [08] > Changer l'email                                     ║",
            "║ [09] > Changer le mot de passe                             ║",
            "║ [10] > Déconnexion du token                                ║",
            "║ [11] > Retour                                              ║",
            "╚═══════════════════════════════════════════════════════════╝",
        ]
        for line in lines:
            console.print(line, style="bold red", justify="center")
        choix = console.input("\n[bold green]Option : [/bold green]").strip().lower()
        choix = choix.zfill(2)
        if choix == "01":
            token_login()
        elif choix == "02":
            token_change_language()
        elif choix == "03":
            token_change_description()
        elif choix == "04":
            token_change_username()
        elif choix == "05":
            token_change_status()
        elif choix == "06":
            token_change_avatar()
        elif choix == "07":
            token_reset_avatar()
        elif choix == "08":
            token_change_email()
        elif choix == "09":
            token_change_password()
        elif choix == "10":
            token_logout()
        elif choix == "11":
            return
        else:
            console.print("[bold red]❌ Choix invalide, réessaie.[/bold red]")
        console.input("[bold yellow]👉 Appuie sur Entrée pour continuer...[/bold yellow]")


def send_sms_twilio():
    console.print("[bold cyan]\n====== Envoi de SMS via Twilio ======[/bold cyan]")
    account_sid = console.input("Entrez votre Account SID Twilio: ").strip()
    auth_token = console.input("Entrez votre Auth Token Twilio: ").strip()
    from_number = console.input("Entrez votre numéro Twilio (from): ").strip()
    to_numbers_input = console.input("Entrez le(s) numéro(s) destinataire(s) séparés par des virgules : ").strip()
    to_numbers = [num.strip() for num in to_numbers_input.split(",")]
    message = console.input("Entrez le message à envoyer : ").strip()
    try:
        client = Client(account_sid, auth_token)
        for to_number in to_numbers:
            message_sent = client.messages.create(
                body=message,
                from_=from_number,
                to=to_number
            )
            console.print(f"[green]Message envoyé à {to_number}, SID: {message_sent.sid}[/green]")
    except Exception as e:
        console.print(f"[red]Erreur d'envoi : {e}[/red]")
    console.input("Entrée pour revenir...")

if __name__ == "__main__":
    console.clear()
    show_startup_banner()
    console.print("[bold green]Bienvenue dans le MultiTool OSINT ![/bold green]")
    update_print()
    spiderman_intro()
    main_menu_page1()