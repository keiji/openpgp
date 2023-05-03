package dev.keiji.openpgp

enum class ImageType(val id: Int) {
    JPEG_InterChange(1),
    ;

    companion object {
        fun findBy(id: Int) = values().firstOrNull { it.id == id }
    }
}
