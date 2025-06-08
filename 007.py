import requests
import time
from thefuzz import process
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box
import socket
import whois
import random 
import hashlib
import os
from bs4 import BeautifulSoup
import folium
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import matplotlib.pyplot as plt
from textblob import TextBlob
import pytesseract
from PIL import Image


console = Console()

headers = {
    "User-Agent": "Mozilla/5.0"
}
TMDB_API_KEY = "06040157f20d0bae45f3bee7bf57566a"  # Ta clé API TMDb
TMDB_BASE_URL = "https://api.themoviedb.org/3"
VT_API_KEY = "03caee030cc5a4b3b0dbf536a33c4c849fd3adad06d3f3297df3c2e56ace3fae"  # Remplace par ta clé API réelle

def tmdb_request(endpoint, params):
    params["api_key"] = TMDB_API_KEY
    url = f"{TMDB_BASE_URL}{endpoint}"
    try:
        r = requests.get(url, params=params, timeout=10)
        if r.status_code == 200:
            return r.json()
        else:
            console.print(f"[red]Erreur API TMDb: {r.status_code}[/red]")
            return None
    except Exception as e:
        console.print(f"[red]Erreur requête TMDb : {e}[/red]")
        return None

import requests

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

    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")

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

    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")


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
    title = Text("007 OSINT", style="bold red", justify="center")
    subtitle = Text("Created by KRATORAK", style="italic green", justify="center")
    panel = Panel(Align.center(Text.assemble(title, "\n", subtitle)), style="bold blue", box=box.DOUBLE)
    console.print(panel)

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

    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")


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
        "Twitch": f"https://www.twitch.tv/{username}",
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
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


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
    num_ips = console.input("💻 Combien d'IP veux-tu générer ? ").strip()

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

    console.input("\n🔄 Appuyez sur Entrée pour revenir au menu...")



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

    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")

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

    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")


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

    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")

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

    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")

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

    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")

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

    else:
        console.print("[red]❌ Erreur : Invitation invalide ou impossible d'obtenir les infos du serveur.[/red]")

    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")


def get_ip_location():
    ip = console.input("💻 Entrez une adresse IP : ").strip()
    console.print(f"\n📍 Géolocalisation de l'IP : [bold yellow]{ip}[/bold yellow]\n")

    r = requests.get(f"https://ipinfo.io/{ip}/json")
    if r.status_code == 200:
        data = r.json()
        console.print(f"🏙️ Ville : {data.get('city', 'Inconnue')}")
        console.print(f"🌎 Pays : {data.get('country', 'Inconnu')}")
        console.print(f"🗺️ Région : {data.get('region', 'Inconnue')}")
        console.print(f"📡 ISP : {data.get('org', 'Inconnu')}")
    else:
        console.print("[red]Impossible d'obtenir des infos sur l'IP.[/red]")

    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")

def data_scraping_osint():
    """ Scraping d’infos sur un sujet (Wikipedia + Google News) """
    console.print("[cyan]🔍 Recherche OSINT sur un sujet[/cyan]")
    query = console.input("🔎 Entrez un sujet : ").strip()

    # Scraping Wikipedia
    wiki_url = f"https://fr.wikipedia.org/wiki/{query.replace(' ', '_')}"
    try:
        response = requests.get(wiki_url)
        soup = BeautifulSoup(response.text, "html.parser")
        intro = soup.find("p").text
        console.print(f"📄 Wikipedia : {intro[:300]}...\n🔗 {wiki_url}")
    except:
        console.print("❌ Impossible d'extraire Wikipedia.")

    # Scraping Google News
    news_url = f"https://www.google.com/search?q={query.replace(' ', '+')}&tbm=nws"
    console.print(f"📰 Articles sur Google News : {news_url}")



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

    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")


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
    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")



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

    console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")


def print_pikachu():
    """ Affiche le titre et un Pikachu stylisé en ASCII """
    console.print(r"""
[bold cyan]
██████╗ ██╗   ██╗███████╗██████╗ ██╗     ██╗   ██╗     ██╗      ██████╗ ██╗   ██╗███████╗
██╔══██╗██║   ██║██╔════╝██╔══██╗██║     ██║   ██║     ██║     ██╔═══██╗██║   ██║██╔════╝
██████╔╝██║   ██║█████╗  ██████╔╝██║     ██║   ██║     ██║     ██║   ██║██║   ██║█████╗  
██╔═══╝ ██║   ██║██╔══╝  ██╔═══╝ ██║     ██║   ██║     ██║     ██║   ██║██║   ██║██╔══╝  
██║     ╚██████╔╝███████╗██║     ███████╗╚██████╔╝     ███████╗╚██████╔╝╚██████╔╝███████╗
╚═╝      ╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝      ╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝
                          B . V . E . R . L . Y     L . O . V . E                          

[/bold cyan]
[bold green]
      ⠀⣀⣤⣤⣶⣶⣶⣶⣤⣀⠀⠀⠀⠀
  ⠀⠀⣴⣿⡿⠛⠉⠙⠛⠛⠻⣿⣿⣷⡄⠀
  ⢀⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⡀
  ⣼⣿⣿⠀⠀⣀⣤⣤⣤⣄⠀⠀⠘⣿⣿⣧                   
  ⣿⣿⣿⡇⠀⠙⠻⠿⠿⠋⠀⠀⢸⣿⣿⣿                        
  ⣿⣿⣿⣿⣷⣶⣤⣤⣤⣶⣾⣿⣿⣿⣿⣿
  ⢿⣿⣿⣿⡿⠿⠛⠛⠛⠿⠿⣿⣿⣿⣿⡿
   ⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉

>> SYSTEM OVERRIDE
>> Injecting payload...
>> EXEC /root/b.verly/hack.sh

╔═══╗──────────────╔╗──────
║╔═╗║────────────╔╝╚╗─────
║║─╚╬══╦══╦══╦═╗╔═╝╔╗╚╦══╗
║║─╔╣╔╗║╔╗║╔╗║╔╗╣╔╗╣║─║╔╗║
║╚═╝║╔╗║╚╝║╚╝║║║║╚╝║╚═╣╚╝║
╚═══╩╝╚╩═╗╠══╩╝╚╩══╩═╗╠══╝
────────╔═╝║─────────╔═╝║
────────╚══╝─────────╚══╝


[/bold green]
[bold red]🔍 KING KRATORAK - OSINT TOOL 🔍[/bold red]
    """)

def main_menu():
    while True:
        clear_console()  # Nettoyage du terminal AVANT d'afficher le menu
        print_pikachu()
        print_header()

        table = Table(title="🎬 007 OSINT TOOL MENU", style="cyan", box=box.ROUNDED)
        table.add_column("Numéro", justify="center", style="bold yellow")
        table.add_column("Option", justify="left", style="bold magenta")
        table.add_column("Description", style="white")

        options = [
            ("1", "🔎 Vérification multi-réseaux sociaux", "Check usernames across social platforms"),
            ("2", "🎥 OSINT FILM ET SÉRIE", "Recherche films et séries avec plateformes légales"),
            ("3", "🌐 WHOIS & DNS Lookup", "Obtenir infos sur un domaine"),
            ("4", "🦠 Vérification URL", "Analyse de site web avec VirusTotal"),
            ("5", "📍 Géolocalisation IP", "Trouver l'emplacement d'une adresse IP"),
            ("6", "⚡ IP GENERATOR", "Génère plusieurs IP et les envoie sur Discord"),
            ("7", "🌍 Les Bons Liens", "Accès rapide aux sites utiles"),
            ("8", "🛡 Website Vulnerability Scanner", "Analyse la sécurité d’un site web"),
            ("9", "🚀 Nitro Stats", "Analyse le nombre de Nitro Boosters d'un serveur"),
            ("10", "🛡 Discord Token Info", "Affiche des infos d’un compte Discord"),
            ("11", "🔗 Discord Webhook Info", "Affiche des infos d’un webhook Discord"),
            ("12", "⚙️ Discord Webhook Generator", "Permet d’envoyer un message avec un webhook"),
            ("13", "🏰 Discord Server Info", "Affiche les infos détaillées d’un serveur via une invitation"),
            ("14", "💎 Nitro Global Stats", "Estimation du nombre de Nitro dans le monde"),
            ("15", "📊 Global Nitro Stat Serveur", "Liste les membres Nitro d'un serveur avec leur rang"),
            ("16", "🌍 Cartes interactives", "Visualisation géographique avec points d’intérêt et heatmaps"),
            ("17", "🔗 Graphiques de réseau", "Analyse des relations entre individus et organisations"),
            ("18", "📊 Dashboards avec KPIs", "Visualisation chronologique et métriques des données OSINT"),
            ("19", "📑 Data Scraping OSINT", "Extraction automatique d’infos publiques sur un sujet"),
            ("20", "💬 Sentiment Analysis", "Analyse des émotions et tendances dans les textes"),
            ("21", "🎭 Détection d’identités multiples", "Recherche d’un pseudo sur plusieurs plateformes"),
            ("22", "🖼️ OCR (Reconnaissance de texte sur image)", "Extraction de texte depuis une image"),
            ("23", "🚨 OSINT Alert System", "Surveillance et alertes sur un sujet clé"),
            ("24", "📊 Analyse avancée des réseaux sociaux", "Détection des influenceurs et connexions entre groupes"),
            ("25", "🌎 Recherche automatique d’articles", "Trouver et classer les sources d’information fiables"),
            ("26", "⏳ Time Analysis", "Suivi de l’évolution des tendances et événements"),
            ("27", "❌ Quitter", "Exit the program"),
        ]

        for num, opt, desc in options:
            table.add_row(num, opt, desc)

        console.print(table)

        choix = console.input("🧠 Choisis un numéro : ").strip()

        if choix == "1":
            social_check_tool()
        elif choix == "2":
            osint_film_serie()
        elif choix == "3":
            get_domain_info()
        elif choix == "4":
            check_url_vt()
        elif choix == "5":
            get_ip_location()
        elif choix == "6":
            ip_generator()
        elif choix == "7":
            show_good_links()
        elif choix == "8":
            website_vulnerability_scanner()
        elif choix == "9":
            invite_code = console.input("🔗 Entrez le code d'invitation du serveur Discord : ").strip()
            get_nitro_boosters(invite_code)
        elif choix == "10":
            discord_token_info()
        elif choix == "11":
            discord_webhook_info()
        elif choix == "12":
            discord_webhook_generator()
        elif choix == "13":
            discord_server_info()
        elif choix == "14":
            get_nitro_global_stats()
        elif choix == "15":
            invite_code = console.input("🔗 Entrez l'invitation du serveur Discord : ").strip()
            global_nitro_stat_server(invite_code)
        elif choix == "16":
            create_map()
        elif choix == "17":
            create_network_graph()
        elif choix == "18":
            create_dashboard()
        elif choix == "19":
            data_scraping_osint()
            console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")  # Pause après exécution
        elif choix == "20":
            sentiment_analysis()
            console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")  # Pause après exécution
        elif choix == "21":
            identity_detection()
            console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")  # Pause après exécution
        elif choix == "22":
            ocr_text_extraction()
            console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")  # Pause après exécution
        elif choix == "23":
            osint_alert_system()
            console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")  # Pause après exécution
        elif choix == "24":
            social_network_analysis()
            console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")  # Pause après exécution
        elif choix == "25":
            article_search()
            console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")  # Pause après exécution
        elif choix == "26":
            time_analysis()
            console.input("\n🔄 Appuie sur Entrée pour revenir au menu...")  # Pause après exécution
        elif choix == "27":
            console.print("\n👋 À bientôt !", style="bold red")
            break
        else:
            console.print("❌ Choix invalide, réessaie.\n", style="bold red")

if __name__ == "__main__":
    main_menu()
