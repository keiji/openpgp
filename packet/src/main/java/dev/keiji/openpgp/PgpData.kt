package dev.keiji.openpgp

import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.nio.charset.StandardCharsets

open class PgpData internal constructor(
    val isAsciiArmor: Boolean,
    val type: Type,
    val blockList: List<Block>,
    var data: ByteArray? = null,
) {
    enum class Type {
        Cleartext,
        Message,
    }

    enum class BlockType(
        val value: String,
    ) {
        PGP_SIGNED_MESSAGE("PGP SIGNED MESSAGE"),
        PGP_MESSAGE("PGP MESSAGE"),
        PGP_PUBLIC_KEY("PGP PUBLIC KEY BLOCK"),
        PGP_PRIVATE_KEY("PGP PRIVATE KEY BLOCK"),
        PGP_SIGNATURE("PGP SIGNATURE"),
        ;

        companion object {
            fun findBy(value: String) = values().firstOrNull { it.value == value }
        }
    }

    class Block(
        val type: BlockType,
        private var _headers: MutableMap<String, String> = mutableMapOf(),
        private val _blockList: MutableList<Block> = mutableListOf(),
    ) {
        val headers: Map<String, String>
            get() = _headers

        val blockList: List<Block>
            get() = _blockList

        var data: ByteArray? = null
        var crc: ByteArray? = null

        @Suppress("CyclomaticComplexMethod")
        fun readFrom(reader: BufferedReader) {
            val sb = StringBuilder()

            var line: String?
            do {
                line = reader.readLine() ?: break

                if (FOOTER_PATTERN.find(line) != null) {
                    break
                }

                // parameter
                val matchParameter = PARAMETER_PATTERN.find(line)
                if (matchParameter != null) {
                    val parameterKey = matchParameter.groupValues[1]
                    val value = line.substring(parameterKey.length + 1).trim()
                    _headers[parameterKey] = value
                    continue
                }

                // new block.
                val matchResult = HEADER_PATTERN.find(line)
                if (matchResult != null) {
                    val pgpDataType = matchResult.groupValues[1]
                    val dataType = BlockType.findBy(pgpDataType)
                        ?: throw InvalidAsciiArmorFormException("Data-type $pgpDataType not supported.")
                    val block = Block(dataType).also {
                        it.readFrom(reader)
                    }
                    _blockList.add(block)
                    continue
                }

                // crc
                if (line.startsWith("=")) {
                    crc = Radix64.decode(line.substring(1))
                } else {
                    sb
                        .append(line)
                        .append("\n")
                }
            } while (line != null)

            val text = sb
                .deleteAt(sb.lastIndex)
                .toString()
                .trimStart()

            if (text.isEmpty()) {
                return
            }

            data = when (type) {
                BlockType.PGP_SIGNED_MESSAGE -> {
                    canonicalize(text)
                }

                else -> {
                    Radix64.decode(text)
                }
            }
        }

        fun writeAsciiArmorTo(outputStream: OutputStream) {
            val writer = OutputStreamWriter(outputStream)

            val header = "${HEADER_DASH}BEGIN ${type.value}${HEADER_DASH}"
            writer.write(header)
            writer.write("\r\n")

            _headers.forEach { key, value ->
                writer.write("$key: $value")
                writer.write("\r\n")
            }

            writer.write("\r\n")

            val dataSnapshot = data ?: return

            val dataStr = if (type == BlockType.PGP_SIGNED_MESSAGE) {
                String(dataSnapshot, charset = StandardCharsets.UTF_8)
            } else {
                val parity = Crc24().let {
                    it.update(ByteArrayInputStream(dataSnapshot))
                    it.value
                }
                val dataEncoded = Radix64.encode(dataSnapshot, charCountOfLine = LINE_CHAR_COUNT)
                val parityEncoded = Radix64.encode(parity)
                "${dataEncoded}\r\n" +
                        "=${parityEncoded}"
            }

            writer.write(dataStr)

            writer.write("\r\n")

            writer.flush()

            _blockList.forEach { block ->
                block.writeAsciiArmorTo(outputStream)
            }

            if (type != BlockType.PGP_SIGNED_MESSAGE) {
                val footer = "${HEADER_DASH}END ${type.value}${HEADER_DASH}"
                writer.write(footer)
                writer.write("\r\n")
            }

            writer.flush()
        }
    }

    fun writeTo(outputStream: OutputStream) {
        if (isAsciiArmor) {
            writeAsciiArmorMessageTo(outputStream)
        } else {
            writeBinaryMessageTo(outputStream)
        }
    }

    private fun writeAsciiArmorMessageTo(outputStream: OutputStream) {
        blockList.forEach { block ->
            block.writeAsciiArmorTo(outputStream)
        }
    }

    private fun writeBinaryMessageTo(outputStream: OutputStream) {
        val dataSnapshot = data ?: return
        outputStream.write(dataSnapshot)
    }

    companion object {
        private const val LINE_CHAR_COUNT = 64

        private const val HEADER_DASH = "-----"
        private val HEADER_DASH_BYTES = HEADER_DASH.toByteArray(charset = StandardCharsets.UTF_8)

        private val HEADER_PATTERN = "-----BEGIN (.*)-----".toRegex()
        private val FOOTER_PATTERN = "-----END (.*)-----".toRegex()
        private val PARAMETER_PATTERN = "^([^:\\s]+): ".toRegex()

        private val LF_PATTERN = "\r(?!\n)|(?<!\r)\n".toRegex()

        fun canonicalize(text: String): ByteArray {
            return text.replace(LF_PATTERN, "\r\n")
                .toByteArray(charset = StandardCharsets.UTF_8)
        }

        fun load(file: File): PgpData {
            return if (isAsciiArmored(file)) {
                loadAsciiArmored(file)
            } else {
                loadBinary(file)
            }
        }

        fun loadBinary(file: File): PgpData {
            return file.inputStream().use {
                loadBinary(it)
            }
        }

        fun loadBinary(inputStream: InputStream): PgpData {
            return PgpData(
                isAsciiArmor = false,
                type = Type.Message,
                blockList = emptyList(),
                data = inputStream.readAllBytes(),
            )
        }

        fun loadAsciiArmored(file: File): PgpData {
            return file.inputStream().use {
                loadAsciiArmored(it)
            }
        }

        fun loadAsciiArmored(inputStream: InputStream): PgpData {
            val reader = inputStream.bufferedReader(charset = StandardCharsets.UTF_8)

            val blockList = mutableListOf<Block>()
            var headerLine: String?

            do {
                headerLine = reader.readLine() ?: break

                val matchResult = HEADER_PATTERN.find(headerLine)
                    ?: throw InvalidAsciiArmorFormException("Invalid header.")

                val pgpDataType = matchResult.groupValues[1]
                val dataType = BlockType.findBy(pgpDataType)
                    ?: throw InvalidAsciiArmorFormException("Data-type $pgpDataType not supported.")

                val block = Block(dataType).also {
                    it.readFrom(reader)
                }
                blockList.add(block)

            } while (headerLine != null)


            val signedMessageBlock = blockList.firstOrNull { it.type == BlockType.PGP_SIGNED_MESSAGE }
            val type = if (signedMessageBlock != null) {
                Type.Cleartext
            } else {
                Type.Message
            }

            return PgpData(
                isAsciiArmor = true,
                type = type,
                blockList = blockList,
            )
        }

        fun isAsciiArmored(file: File): Boolean {
            return file.inputStream().use {
                isAsciiArmored(it)
            }
        }

        fun isAsciiArmored(inputStream: InputStream): Boolean {
            if (inputStream.markSupported()) {
                // Read only the beginning that is necessary for the decision, instead of loading all the data.
                @Suppress("MagicNumber")
                inputStream.mark(512)
            }

            val headerFrontBytes = ByteArray(HEADER_DASH_BYTES.size).also {
                inputStream.read(it)
            }
            if (!headerFrontBytes.contentEquals(HEADER_DASH_BYTES)) {
                return false
            }

            val headerLine = HEADER_DASH + (inputStream.bufferedReader().readLine())

            val matchResult = HEADER_PATTERN.find(headerLine)
            matchResult ?: return false

            val pgpDataType = matchResult.groupValues[1]

            val dataType = BlockType.findBy(pgpDataType)

            if (inputStream.markSupported()) {
                inputStream.reset()
            }

            return dataType != null
        }
    }
}

