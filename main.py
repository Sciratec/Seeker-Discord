from discord.ext import commands
from os import getenv
from dotenv import load_dotenv
from ht import hatchingTriage
from urlscan import urlSearch, urlScan
from re import search


load_dotenv()
BOT_TOKEN = getenv('DISCORD_TOKEN')

client = commands.Bot(command_prefix='!')
                    
@client.event
async def on_ready():
    print(f'Bot: {client.user} ready!.')

@client.event
async def on_message(message):
    if message.author == client.user:
        return
    msg = message.content
    await client.process_commands(message)

@client.command(name="usearch", brief="Search for an artifact on urlscan", description="Search for an artifact on urlscan")
async def usearch(ctx, artifact):
    ip_regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    protocol_regex = "^http|https"

    if search(protocol_regex, artifact):
        await ctx.message.delete()
        await ctx.send("Do not use HTTP/HTTPS in your search - stops Discord from previewing potentially malicious sites!")
    elif search(ip_regex, artifact):
        await ctx.message.delete()
        await ctx.send("IPs not implemented yet! Sorry.")
    else:
        times_seen, time_split, has_more, recent_screenshot = urlSearch(artifact)
        if times_seen == 10000 and has_more == True:
            await ctx.send(f"```Seen more than {times_seen} times\nRecently Seen: {time_split[0]}```")
            await ctx.send(recent_screenshot)
        elif times_seen == 0:
            await ctx.send("Did not find domain")
        else:
            if times_seen == 0:
                await ctx.send("Did not find domain")
            else:
                await ctx.send(f"```Times seen: {times_seen}\nRecently Seen: {time_split[0]}```")
                await ctx.send("Recent Screenshot:")
                await ctx.send(recent_screenshot)
         

@client.command(name="uscan", brief="Scan an artifact on urlscan", description="Scan an artifact on urlscan")
async def uscan(ctx, artifact):
    protocol_regex = "^http|https"

    if search(protocol_regex, artifact):
        await ctx.message.delete()
        await ctx.send("Do not use HTTP/HTTPS in your search - stops Discord from previewing potentially malicious sites!")
    else:
        await ctx.send(f"Please allow 30-35 seconds for the report to propagate")
        error, report_url, screenshot, overall_verdict, urlscan_verdict, engines_verdict, community_verdict, filename, filesize, mime_description, file_hash = urlScan(artifact)
        if error:
            await ctx.send(error)
        else:
            await ctx.send(f"```Report URL: {report_url}```")
            await ctx.send(f"{screenshot}")
            await ctx.send(f"```Verdicts:\nOverall: {overall_verdict}\nUrlscan:{urlscan_verdict}\nEngines: {engines_verdict}\nCommunity: {community_verdict}```")
            if filename or filesize or mime_description or filesize or file_hash:
                await ctx.send("Downloadable file detected:")
                await ctx.send(f"```Filename: {filename}\nFilesize: {filesize} bytes\nFile Description: {mime_description}\nFile Hash: {file_hash}```")

@client.command(name="ht", brief="Search Hatching Triage by using a SHA256 hash", description="Search Hatching Triage and pull IOCS/Configs. Example: !ht <SHA256>")
async def ht(ctx, sha256Hash):

    user = ctx.author

    if ctx.channel.name == ("seeker-search"):
        c2s, cncURLs, iocURLs, iocIPS, signatures = hatchingTriage(sha256Hash)

        await user.send(f"Results for {sha256Hash}:")

        if iocURLs and type(iocURLs) == list:
            await user.send("IOC Domain(s):")
            stripped_domains = "\n".join(iocURLs)
            await user.send(f"```{stripped_domains}```")
        if iocIPS and type(iocIPS) == list:
            await user.send("\n\nIOC IP(s):")
            stripped_ips = "\n".join(iocIPS)
            await user.send(f"```{stripped_ips}```")
        if c2s and type(c2s) == list:
            await user.send("\n\nRule/C2:")
            for a in c2s:
                stripped_c2s = "/".join(a)
                await user.send(f"```{stripped_c2s}```")
        if cncURLs and type(cncURLs) == list:
            await user.send("\n\nC2 URL(s):")
            for a in cncURLs:
                stripped_cnc = "\n".join(a)
                await user.send(f"```{stripped_cnc}```")
        if signatures and type(signatures) == list:
            await user.send("\nSignatures:")
            for a in signatures:
                stripped_sig = ", ".join(a)
                await user.send(f"```{stripped_sig}```")

@ht.error
async def ht_error(ctx, error):
    if ctx.channel.name == ("seeker-search"):
        if isinstance(error, commands.MissingRequiredArgument):
            await ctx.send("Provide SHA256 to search.")

@uscan.error
async def uscan_error(ctx, error):
    if ctx.channel.name == ("seeker-search"):
        if isinstance(error, commands.MissingRequiredArgument):
            await ctx.send("Provide IP or a domain to scan.")

@usearch.error
async def usearch_error(ctx, error):
    if ctx.channel.name == ("seeker-search"):
        if isinstance(error, commands.MissingRequiredArgument):
            await ctx.send("Provide a domain to search.")


@client.command(name="purge")
@commands.has_role('Owner')
async def clear(ctx):
    await ctx.channel.purge()

client.run(BOT_TOKEN)