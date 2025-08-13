import requests
import json
import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

console = Console()

class DiscordNuker:
    def __init__(self, token):
        self.token = token
        self.headers = {
            "Authorization": token,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        self.base_url = "https://discord.com/api/v9"
        
    def get_user_info(self):
        """Récupère les informations de l'utilisateur"""
        try:
            response = requests.get(f"{self.base_url}/users/@me", headers=self.headers)
            if response.status_code == 200:
                return response.json()
            else:
                console.print(f"[red]Erreur lors de la récupération des infos: {response.status_code}[/red]")
                return None
        except Exception as e:
            console.print(f"[red]Erreur: {e}[/red]")
            return None
    
    def remove_all_friends(self):
        """Supprime tous les amis"""
        console.print("[yellow]Suppression de tous les amis...[/yellow]")
        try:
            # Récupérer la liste des amis
            friends_response = requests.get(f"{self.base_url}/users/@me/relationships", headers=self.headers)
            if friends_response.status_code == 200:
                friends = friends_response.json()
                removed_count = 0
                
                for friend in friends:
                    if friend['type'] == 1:  # Type 1 = ami
                        user_id = friend['id']
                        # Supprimer l'ami
                        delete_response = requests.delete(
                            f"{self.base_url}/users/@me/relationships/{user_id}",
                            headers=self.headers
                        )
                        if delete_response.status_code == 204:
                            removed_count += 1
                            console.print(f"[green]Ami {user_id} supprimé[/green]")
                        else:
                            console.print(f"[red]Erreur suppression ami {user_id}[/red]")
                
                console.print(f"[green]✅ {removed_count} amis supprimés[/green]")
                return True
            else:
                console.print(f"[red]Erreur récupération amis: {friends_response.status_code}[/red]")
                return False
        except Exception as e:
            console.print(f"[red]Erreur suppression amis: {e}[/red]")
            return False
    
    def remove_profile_picture(self):
        """Supprime la photo de profil"""
        console.print("[yellow]Suppression de la photo de profil...[/yellow]")
        try:
            payload = {"avatar": None}
            response = requests.patch(f"{self.base_url}/users/@me", headers=self.headers, json=payload)
            if response.status_code == 200:
                console.print("[green]✅ Photo de profil supprimée[/green]")
                return True
            else:
                console.print(f"[red]Erreur suppression photo: {response.status_code}[/red]")
            return False
        except Exception as e:
            console.print(f"[red]Erreur suppression photo: {e}[/red]")
            return False
    
    def leave_all_servers(self):
        """Quitte tous les serveurs"""
        console.print("[yellow]Quittage de tous les serveurs...[/yellow]")
        try:
            # Récupérer la liste des serveurs
            guilds_response = requests.get(f"{self.base_url}/users/@me/guilds", headers=self.headers)
            if guilds_response.status_code == 200:
                guilds = guilds_response.json()
                left_count = 0
                
                for guild in guilds:
                    guild_id = guild['id']
                    # Quitter le serveur
                    leave_response = requests.delete(
                        f"{self.base_url}/users/@me/guilds/{guild_id}",
                        headers=self.headers
                    )
                    if leave_response.status_code == 204:
                        left_count += 1
                        console.print(f"[green]Serveur {guild['name']} quitté[/green]")
                    else:
                        console.print(f"[red]Erreur quit serveur {guild['name']}[/red]")
                
                console.print(f"[green]✅ {left_count} serveurs quittés[/green]")
                return True
            else:
                console.print(f"[red]Erreur récupération serveurs: {guilds_response.status_code}[/red]")
                return False
        except Exception as e:
            console.print(f"[red]Erreur quit serveurs: {e}[/red]")
            return False
    
    def nuke_account(self):
        """Exécute toutes les actions de nuke"""
        console.print(Panel(
            Align.center(Text.assemble(
                ("🎯 ", "bold red"),
                ("DISCORD ACCOUNT NUKER", "bold red"),
                (" 🎯", "bold red")
            )),
            style="bold red"
        ))
        
        # Vérification du token
        user_info = self.get_user_info()
        if not user_info:
            console.print("[red]Token invalide ou erreur de connexion[/red]")
            return False
        
        username = user_info.get('username', 'Inconnu')
        discriminator = user_info.get('discriminator', '0000')
        console.print(f"[cyan]Compte: {username}#{discriminator}[/cyan]")
        
        # Confirmation
        confirm = console.input("[red]Tapez 'NUKE' pour confirmer la destruction du compte: [/red]")
        if confirm != "NUKE":
            console.print("[yellow]Opération annulée[/yellow]")
            return False
        
        console.print("[red]🚀 Lancement du nuke...[/red]")
        
        # Exécuter toutes les actions
        results = {
            "Amis supprimés": self.remove_all_friends(),
            "Photo de profil supprimée": self.remove_profile_picture(),
            "Serveurs quittés": self.leave_all_servers()
        }
        
        # Afficher les résultats
        console.print(Panel(
            "\n".join([f"{k}: {'✅' if v else '❌'}" for k, v in results.items()]),
            title="Résultats du Nuke",
            style="bold green"
        ))
        
        return all(results.values())

    def main(self):
        def show_menu():
            console.clear()
            console.print(Panel(
                Align.center(Text.assemble(
                    ("🎯 ", "bold red"),
                    ("DISCORD ADVANCED TOOLS MENU", "bold red"),
                    (" 🎯", "bold red")
                )),
                style="bold red"
            ))
            console.print("╔══════════════════════════════════════════════════════════════════════════╗", style="bold red", justify="center")
            console.print("║ [01] Mass DM         [10] Mass Ping                                  ║", style="bold red", justify="center")
            console.print("║ [02] Dm Spam         [11] Button Click                               ║", style="bold red", justify="center")
            console.print("║ [03] React Verify    [12] Friender                                   ║", style="bold red", justify="center")
            console.print("║ [04] Joiner          [13] Token Menu                                 ║", style="bold red", justify="center")
            console.print("║ [05] Leaver          [14] Booster                                    ║", style="bold red", justify="center")
            console.print("║ [06] Accept Rules    [15] VoiceChat                                  ║", style="bold red", justify="center")
            console.print("║ [07] Raid Channel    [16] SoundBoard                                 ║", style="bold red", justify="center")
            console.print("║ [08] Scrape Users    [17] OnBoarding                                 ║", style="bold red", justify="center")
            console.print("║ [09] Check Tokens    [18] Server Info                                ║", style="bold red", justify="center")
            console.print("╚══════════════════════════════════════════════════════════════════════════╝", style="bold red", justify="center")

        def mass_dm():
            console.print("[yellow]Mass DM - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def dm_spam():
            console.print("[yellow]DM Spam - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def react_verify():
            console.print("[yellow]React Verify - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def joiner():
            console.print("[yellow]Joiner - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def leaver():
            console.print("[yellow]Leaver - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def accept_rules():
            console.print("[yellow]Accept Rules - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def raid_channel():
            console.print("[yellow]Raid Channel - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def scrape_users():
            console.print("[yellow]Scrape Users - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def check_tokens():
            console.print("[yellow]Check Tokens - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def mass_ping():
            console.print("[yellow]Mass Ping - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def button_click():
            console.print("[yellow]Button Click - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def friender():
            console.print("[yellow]Friender - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def token_menu():
            console.print("[yellow]Token Menu - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def booster():
            console.print("[yellow]Booster - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def voice_chat():
            console.print("[yellow]VoiceChat - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def sound_board():
            console.print("[yellow]SoundBoard - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def onboarding():
            console.print("[yellow]OnBoarding - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        def server_info():
            console.print("[yellow]Server Info - Fonctionnalité avancée[/yellow]")
            console.input("Appuie sur Entrée pour revenir au menu...")

        actions = {
            "01": mass_dm,
            "02": dm_spam,
            "03": react_verify,
            "04": joiner,
            "05": leaver,
            "06": accept_rules,
            "07": raid_channel,
            "08": scrape_users,
            "09": check_tokens,
            "10": mass_ping,
            "11": button_click,
            "12": friender,
            "13": token_menu,
            "14": booster,
            "15": voice_chat,
            "16": sound_board,
            "17": onboarding,
            "18": server_info,
        }

        while True:
            show_menu()
            choice = console.input("\n[bold green]Choisissez une option (ou 'q' pour quitter) : [/bold green]").strip()
            if choice.lower() == 'q':
                break
            action = actions.get(choice)
            if action:
                action()
            else:
                console.print("[red]Choix invalide, réessayez.[/red]")

if __name__ == "__main__":
    nuker = DiscordNuker("")
    nuker.main()
