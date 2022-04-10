from discord.ext import commands
from os import getenv
from dotenv import load_dotenv
from matplotlib.pyplot import isinteractive
from vt import virustotal
from ht import hatchingTriage

load_dotenv()
BOT_TOKEN = getenv('DISCORD_TOKEN')

client = commands.Bot(command_prefix='!')
                    
@client.event
async def on_ready():
    print(f'Bot: {client.user} is now live.')

# @client.event
# async def on_message(message):
#     if message.author == client.user:
#         return
#     msg = message.content
#     await client.process_commands(message)

# @client.command(name="vt", description="Search Virustotal and pull IOCS. Example: !vt <SHA256>")
# async def vt(ctx, sha256Hash):
    
#     if ctx.channel.name == ("malware-analysis"):
#         names, url, ips, context, domainRelation = virustotal(sha256Hash)
    
#         # if context and type(context) == list:
#         #     await ctx.send("Context:")
#         #     for a, b in context:
#         #         await ctx.send(f"{a}, {b}")

#         if names and type(names) == list:
#             await ctx.send("Malware Names(s):")
#             stripped_names = ", ".join(names)
#             await ctx.send(stripped_names)

#         if url and type(url) == list:
#             await ctx.send("Contacted URLS:")
#             stripped_domains = ", ".join(url)
#             await ctx.send(stripped_domains)

#         if ips and type(ips) == list:
#             await ctx.send("IP IoCs:")
#             stripped_ips = ", ".join(ips)
#             await ctx.send(stripped_ips)
    
#         if domainRelation and type(domainRelation) == list:
#             await ctx.send("Relational Domain(s):")
#             stripped_other = ", ".join(domainRelation)
#             await ctx.send(stripped_other)

@client.command(name="ht", brief="Search Hatching Triage by using a SHA256 hash", description="Search Hatching Triage and pull IOCS/Configs. Example: !ht <SHA256>")
async def ht(ctx, sha256Hash):

    if ctx.channel.name == ("malware-analysis"):
        c2s, cncURLs, iocURLs, iocIPS, signatures = hatchingTriage(sha256Hash)

        if iocURLs and type(iocURLs) == list:
            await ctx.send("IOC Domain(s):")
            stripped_domains = "\n".join(iocURLs)
            await ctx.send(stripped_domains)
        if iocIPS and type(iocIPS) == list:
            await ctx.send("\n\nIOC IP(s):")
            stripped_ips = "\n".join(iocIPS)
            await ctx.send(stripped_ips)
        if c2s and type(c2s) == list:
            await ctx.send("\n\nRule/C2:")
            for a in c2s:
                stripped_c2s = "/".join(a)
                await ctx.send(stripped_c2s)
        if cncURLs and type(cncURLs) == list:
            await ctx.send("\n\nC2 URL(s):")
            for a in cncURLs:
                stripped_cnc = "\n".join(a)
                await ctx.send(stripped_cnc)
        if signatures and type(signatures) == list:
            await ctx.send("\nSignatures:")
            for a in signatures:
                stripped_sig = ", ".join(a)
                await ctx.send(stripped_sig)

@ht.error
async def ht_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("Provide SHA256 to search.")

@client.command(name="clear")
@commands.has_role('Owner')
async def clear(ctx):
    await ctx.channel.purge()

client.run(BOT_TOKEN)