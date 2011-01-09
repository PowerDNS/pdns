<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:fo="http://www.w3.org/1999/XSL/Format"
                version="1.0">
  <!-- Use ids for filenames -->
  <xsl:param name="use.id.as.filename" select="'1'"/>
  <!-- Turn on admonition graphics. -->
  <xsl:param name="admon.graphics" select="'1'"/>
  <xsl:param name="admon.graphics.path"></xsl:param>
  <!-- Configure the stylesheet to use -->
  <xsl:param name="html.stylesheet" select="'docbook.css'"/>

<xsl:param name="chunk.section.depth" select="1"></xsl:param>

<xsl:param name="callout.graphics" select="'1'"></xsl:param>
<xsl:param name="callout.graphics.path"></xsl:param>
<xsl:param name="callout.list.table" select="'1'"></xsl:param>
<xsl:param name="generate.section.toc.level" select="1"></xsl:param>
<xsl:param name="section.autolabel" select="1"></xsl:param>
<xsl:param name="section.autolabel.max.depth" select="2"></xsl:param>
<xsl:param name="generate.index" select="1"></xsl:param>

</xsl:stylesheet>
